//! Приёмная сторона сквозного flow-control потока: кредитное окно с автонастройкой.
//!
//! ## Зачем
//!
//! Нога туннеля — одно TCP-соединение на МНОГО потоков, поэтому она не может
//! притормозить один медленный поток, не заблокировав остальные. Раньше отправитель
//! (сервер, читающий цель) вообще не знал, как быстро приёмник (клиентский стек)
//! забирает данные: всё, что приёмник не успевал отдать приложению, копилось в
//! его памяти, а после лимита бэклога поток просто убивали. На спидтесте при
//! скорости выше, чем клиент способен прокачать через TUN, это и есть «переполнение
//! буферов на пике» — часть потоков умирала, остальные забирали всю полосу.
//!
//! Решение — то же, что у TCP/HTTP2/QUIC: **приёмник сообщает, сколько ещё готов
//! принять**. Окно растёт вместе со скоростью потребления (аналог Linux
//! `tcp_rcv_space_adjust`/DRS: `окно ≈ 2 × скорость × RTT`), поэтому быстрый поток
//! не упирается в окно, а медленный не может накопить у приёмника больше окна.
//!
//! ## Протокол
//!
//! Кадр [`FrameType::Credit`](crate::nrxp::FrameType) с `u32` BE в payload — это
//! **абсолютный** лимит: «можешь отправить в сумме до N байт Data этого потока»
//! (по модулю 2³², сравнение через знаковую разность). Абсолютное значение
//! идемпотентно: потерянный или продублированный кадр ничего не ломает, следующий
//! чинит состояние. Отправитель без единого гранта не ограничен — так старые
//! пиры, не знающие про кредиты, продолжают работать как раньше.
//!
//! ## Что здесь
//!
//! Только чистая арифметика окна ([`CreditReceiver`]): ни сети, ни каналов, ни
//! времени из системы — `now` и `rtt` приходят снаружи, поэтому логика тестируется
//! детерминированно.

use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

/// Окно, которое приёмник обещает сразу при открытии потока (первый абсолютный
/// лимит). Покрывает ответ небольшой страницы целиком без единого обмена кредитами.
pub const CREDIT_INITIAL_WINDOW: u32 = 1024 * 1024;
/// Нижняя граница окна: ниже поток упирался бы в кредит на каждом RTT.
pub const CREDIT_MIN_WINDOW: u32 = 256 * 1024;
/// Верхняя граница окна одного потока. Столько максимум может лежать у приёмника в
/// буферах, если приложение читает медленно.
pub const CREDIT_MAX_WINDOW: u32 = 16 * 1024 * 1024;
/// Общий бюджет окон всех потоков процесса. Аналог `tcp_mem`: когда потоков много,
/// каждому достаётся доля бюджета, а не `CREDIT_MAX_WINDOW`, и память приёмника
/// ограничена независимо от числа соединений (спидтест открывает десятки).
pub const CREDIT_GLOBAL_BUDGET: u64 = 64 * 1024 * 1024;
/// Грант отправляется, когда накопилось не меньше `окно / CREDIT_GRANT_DIVISOR`
/// неанонсированных байт — не на каждый кадр (мелкие управляющие кадры), но и не
/// настолько редко, чтобы отправитель успевал упереться в лимит.
const CREDIT_GRANT_DIVISOR: u32 = 4;
/// Минимальный шаг гранта в байтах (не засорять туннель кредитами для мелких окон).
const CREDIT_MIN_GRANT: u64 = 64 * 1024;
/// Окно измерения скорости потребления (долей RTT ниже ограничено этими пределами).
const MEASURE_MIN: Duration = Duration::from_millis(40);
const MEASURE_MAX: Duration = Duration::from_millis(500);

/// Сумма «обещанных, но ещё не потреблённых» байт по всем потокам процесса.
static GLOBAL_OUTSTANDING: AtomicU64 = AtomicU64::new(0);
/// Число живых приёмников — делитель общего бюджета.
static ACTIVE_RECEIVERS: AtomicU64 = AtomicU64::new(0);

/// Окно приёмника одного потока.
#[derive(Debug)]
pub struct CreditReceiver {
    /// Сколько байт приёмник разрешает держать «в полёте + в своих буферах».
    window: u32,
    /// Абсолютный лимит, уже объявленный отправителю.
    granted: u64,
    /// Сколько байт отдано локальному потребителю (из буфера приёмника — дальше).
    consumed: u64,
    /// Начало текущего окна измерения скорости и байты, потреблённые в нём.
    measure_start: Option<Instant>,
    measure_bytes: u64,
}

impl Default for CreditReceiver {
    fn default() -> Self {
        Self::new()
    }
}

impl CreditReceiver {
    pub fn new() -> Self {
        GLOBAL_OUTSTANDING.fetch_add(CREDIT_INITIAL_WINDOW as u64, Ordering::Relaxed);
        ACTIVE_RECEIVERS.fetch_add(1, Ordering::Relaxed);
        Self {
            window: CREDIT_INITIAL_WINDOW,
            granted: CREDIT_INITIAL_WINDOW as u64,
            consumed: 0,
            measure_start: None,
            measure_bytes: 0,
        }
    }

    /// Первый абсолютный лимит — его отправитель получает сразу после `Connect`.
    pub fn initial_offset() -> u32 {
        CREDIT_INITIAL_WINDOW
    }

    /// Текущее окно (для логов и тестов).
    pub fn window(&self) -> u32 {
        self.window
    }

    /// Сколько байт отправитель ещё вправе прислать (обещано − потреблено).
    pub fn outstanding(&self) -> u64 {
        self.granted.saturating_sub(self.consumed)
    }

    /// Потолок окна этого потока: справедливая доля общего бюджета.
    fn window_cap() -> u64 {
        let active = ACTIVE_RECEIVERS.load(Ordering::Relaxed).max(1);
        (CREDIT_GLOBAL_BUDGET / active).clamp(CREDIT_MIN_WINDOW as u64, CREDIT_MAX_WINDOW as u64)
    }

    /// Приёмник отдал потребителю `n` байт. Возвращает новый абсолютный лимит, если
    /// пора отправить грант. `rtt` — оценка RTT туннеля (для автонастройки окна).
    pub fn on_consumed(&mut self, n: usize, now: Instant, rtt: Duration) -> Option<u32> {
        self.consumed += n as u64;
        self.measure_bytes += n as u64;
        self.autotune(now, rtt);

        // Потреблённое уходит из общего счёта «обещано, но не потреблено»…
        sub_outstanding(n as u64);

        // …а отправителю нужно, чтобы на руках всегда было `window` байт сверх уже
        // потреблённого.
        let target = self.consumed + self.window as u64;
        let unannounced = target.saturating_sub(self.granted);
        let threshold = (self.window as u64 / CREDIT_GRANT_DIVISOR as u64).max(CREDIT_MIN_GRANT);
        if unannounced < threshold {
            return None;
        }

        GLOBAL_OUTSTANDING.fetch_add(unannounced, Ordering::Relaxed);
        self.granted = target;
        Some(self.granted as u32)
    }

    /// Автонастройка окна по скорости потребления: `окно ≥ 2 × (байт за RTT)`.
    /// Окно только растёт в пределах потолка — иначе колебания скорости
    /// превращались бы в колебания кредита и в лишние остановки отправителя.
    fn autotune(&mut self, now: Instant, rtt: Duration) {
        let interval = rtt.clamp(MEASURE_MIN, MEASURE_MAX);
        let Some(start) = self.measure_start else {
            self.measure_start = Some(now);
            return;
        };
        let elapsed = now.saturating_duration_since(start);
        if elapsed < interval {
            return;
        }
        // Байты, потреблённые за один RTT, при пересчёте на фактический интервал.
        let per_rtt = (self.measure_bytes as f64 * (interval.as_secs_f64() / elapsed.as_secs_f64()))
            as u64;
        self.measure_start = Some(now);
        self.measure_bytes = 0;

        let wanted = per_rtt.saturating_mul(2).max(CREDIT_MIN_WINDOW as u64);
        let cap = Self::window_cap();
        let wanted = wanted.min(cap);
        if wanted > self.window as u64 {
            self.window = wanted as u32;
        } else if self.window as u64 > cap {
            // Потоков стало больше — окно поджимается до своей доли бюджета.
            self.window = cap as u32;
        }
    }
}

impl Drop for CreditReceiver {
    fn drop(&mut self) {
        sub_outstanding(self.outstanding());
        ACTIVE_RECEIVERS.fetch_sub(1, Ordering::Relaxed);
    }
}

/// Убавляет общий счёт, не уходя ниже нуля (счёт общий для потоков и тестов).
fn sub_outstanding(n: u64) {
    let _ = GLOBAL_OUTSTANDING.fetch_update(Ordering::Relaxed, Ordering::Relaxed, |v| {
        Some(v.saturating_sub(n))
    });
}

/// Продолжает 32-битное абсолютное значение из `Credit`-кадра до 64 бит относительно
/// текущего лимита. `None`, если лимит не вырос (дубликат/старый кадр).
pub(crate) fn extend_limit(current: u64, wire: u32) -> Option<u64> {
    let delta = wire.wrapping_sub(current as u32) as i32;
    (delta > 0).then(|| current + delta as u64)
}

#[cfg(test)]
mod tests {
    use super::*;

    const RTT: Duration = Duration::from_millis(100);

    /// Тесты делят глобальные счётчики — один за другим, не параллельно.
    static SERIAL: std::sync::Mutex<()> = std::sync::Mutex::new(());

    #[test]
    fn small_transfers_never_need_a_grant() {
        let _g = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
        let mut rx = CreditReceiver::new();
        let t0 = Instant::now();
        // 100 КБ ответа — ниже порога в четверть окна.
        assert_eq!(rx.on_consumed(100 * 1024, t0, RTT), None);
        assert_eq!(rx.outstanding(), CREDIT_INITIAL_WINDOW as u64 - 100 * 1024);
    }

    #[test]
    fn grant_tops_the_window_up_once_a_quarter_was_consumed() {
        let _g = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
        let mut rx = CreditReceiver::new();
        let t0 = Instant::now();
        let quarter = (CREDIT_INITIAL_WINDOW / 4) as usize;
        assert_eq!(rx.on_consumed(quarter - 1, t0, RTT), None);
        let offset = rx.on_consumed(1, t0, RTT).expect("quarter consumed → grant");
        // Лимит = потреблено + окно: у отправителя снова ровно `window` байт запаса.
        assert_eq!(offset as u64, quarter as u64 + CREDIT_INITIAL_WINDOW as u64);
        assert_eq!(rx.outstanding(), CREDIT_INITIAL_WINDOW as u64);
    }

    #[test]
    fn window_grows_with_the_consumption_rate() {
        let _g = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
        let mut rx = CreditReceiver::new();
        let mut now = Instant::now();
        // 8 МБ за каждый RTT: окно обязано дорасти до ~16 МБ (≥ 2×BDP), а не остаться 1 МБ.
        for _ in 0..4 {
            for _ in 0..8 {
                rx.on_consumed(1024 * 1024, now, RTT);
                now += RTT / 8;
            }
        }
        assert!(
            rx.window() >= 8 * 1024 * 1024,
            "window stayed at {} for an 8 MB/RTT consumer",
            rx.window()
        );
        assert!(rx.window() <= CREDIT_MAX_WINDOW);
    }

    #[test]
    fn a_slow_consumer_keeps_a_small_window() {
        let _g = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
        let mut rx = CreditReceiver::new();
        let mut now = Instant::now();
        // 64 КБ за RTT — окно остаётся у минимума, у приёмника не копится лишнего.
        for _ in 0..20 {
            rx.on_consumed(64 * 1024, now, RTT);
            now += RTT;
        }
        assert!(rx.window() <= CREDIT_INITIAL_WINDOW, "window = {}", rx.window());
    }

    #[test]
    fn extend_limit_handles_wraparound_and_stale_frames() {
        assert_eq!(extend_limit(1000, 5000), Some(5000));
        // Старый/дубликат — не двигает лимит назад.
        assert_eq!(extend_limit(5000, 1000), None);
        assert_eq!(extend_limit(5000, 5000), None);
        // Перенос через 2³².
        let near = u32::MAX as u64 - 10;
        assert_eq!(extend_limit(near, 20), Some(u32::MAX as u64 + 21));
    }

    #[test]
    fn dropping_a_receiver_returns_its_budget() {
        let _g = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
        let before = GLOBAL_OUTSTANDING.load(Ordering::Relaxed);
        let active = ACTIVE_RECEIVERS.load(Ordering::Relaxed);
        {
            let _rx = CreditReceiver::new();
            assert_eq!(
                GLOBAL_OUTSTANDING.load(Ordering::Relaxed),
                before + CREDIT_INITIAL_WINDOW as u64
            );
        }
        assert_eq!(GLOBAL_OUTSTANDING.load(Ordering::Relaxed), before);
        assert_eq!(ACTIVE_RECEIVERS.load(Ordering::Relaxed), active);
    }
}
