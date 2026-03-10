use jni::errors::Error as JniError;
use jni::objects::{JObject, JString, JValue};
use tauri::command;

#[command]
pub fn start_vpn_android(remote_address: String) -> Result<i32, String> {
    #[cfg(target_os = "android")]
    {
        let ctx = ndk_context::android_context();
        let vm_ptr = ctx.vm() as *mut jni::sys::JavaVM;

        let vm = unsafe { jni::JavaVM::from_raw(vm_ptr) }.map_err(|e: JniError| e.to_string())?;

        let mut env = vm
            .attach_current_thread()
            .map_err(|e: JniError| e.to_string())?;

        let class_name = "com/netrunner/vpn/NetrunnerVpnService";
        let class = env
            .find_class(class_name)
            .map_err(|e: JniError| e.to_string())?;

        let companion = env
            .get_static_field(
                class,
                "Companion",
                "Lcom/netrunner/vpn/NetrunnerVpnService$Companion;",
            )
            .map_err(|e: JniError| e.to_string())?
            .l()
            .map_err(|e: JniError| e.to_string())?;

        let j_remote_addr = env
            .new_string(remote_address)
            .map_err(|e: JniError| e.to_string())?;

        // Явное приведение контекста к JObject
        let context_obj = unsafe { JObject::from_raw(ctx.context() as *mut _) };

        let result = env
            .call_method(
                companion,
                "startVpn",
                "(Landroid/app/Activity;Ljava/lang/String;)I",
                &[JValue::Object(&context_obj), JValue::Object(&j_remote_addr)],
            )
            .map_err(|e: JniError| e.to_string())?;

        result.i().map_err(|e: JniError| e.to_string())
    }

    #[cfg(not(target_os = "android"))]
    {
        Err("VPN доступен только на Android".into())
    }
}
