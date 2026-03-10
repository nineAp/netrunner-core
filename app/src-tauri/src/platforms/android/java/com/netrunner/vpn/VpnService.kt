package com.netrunner.vpn

import android.app.Activity
import android.content.Intent
import android.net.VpnService
import android.os.ParcelFileDescriptor
import uniffi.netrunner_client.SessionManager

class NetrunnerVpnService : VpnService() {

    companion object {

        private var vpnInterface: ParcelFileDescriptor? = null

        fun start(activity: Activity): Int {
            val intent = VpnService.prepare(activity)

            if (intent != null) {
                activity.startActivityForResult(intent, 1001)
                return -1
            }

            return startVpn(activity)
        }
        @JvmStatic
        fun startVpn(activity: Activity, remoteAddress: String): Int {
            val builder = Builder()

            builder.setSession("NetrunnerVPN")
                .addAddress("10.0.0.1", 32)
                .addRoute("0.0.0.0", 0)
                .setMtu(1500)

            vpnInterface = builder.establish()
            val fd = vpnInterface?.fd ?: -1

            if (fd != -1) {
                try {
                    // 1. Создаем менеджер сессий
                    val sessionManager = uniffi.netrunner_client.SessionManager()
                    
                    // 2. Вызываем метод start, прокидывая адрес и дескриптор
                    // Обратите внимание: метод .start() возвращает объект Session
                    sessionManager.start(
                        remoteAddress = remoteAddress, // Ваша пустая строка или адрес
                        tunFd = fd
                    )
                    
                    Log.d("NetrunnerVPN", "Сессия успешно запущена с FD: $fd")
                } catch (e: Exception) {
                    Log.e("NetrunnerVPN", "Ошибка при запуске Rust-сессии: ${e.message}")
                    stop() // Закрываем интерфейс, если нативная часть не стартанула
                    return -1
                }
            }

            return fd
        }
        fun stop() {
            vpnInterface?.close()
            vpnInterface = null
        }
    }
}