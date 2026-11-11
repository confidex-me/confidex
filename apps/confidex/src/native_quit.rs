//! Route macOS Quit through the same decision as the root close button.
use eframe::egui;
use objc2::{
    Encode, MainThreadMarker, ffi, msg_send,
    runtime::{AnyClass, AnyObject, Imp, Sel},
    sel,
};
use std::{cell::RefCell, ffi::CString};

thread_local! {
    static CONTEXT: RefCell<Option<egui::Context>> = const { RefCell::new(None) };
}

extern "C-unwind" fn should_terminate(_: &AnyObject, _: Sel, _: Option<&AnyObject>) -> usize {
    CONTEXT.with(|context| {
        if let Some(ctx) = context.borrow().as_ref() {
            confidex_ui::VaultApp::request_close(ctx);
        }
    });
    0 // NSTerminateCancel leaves the run loop alive for the shared confirmation.
}

fn implementation() -> Imp {
    // The method encoding below matches this function's Cocoa ABI.
    unsafe {
        std::mem::transmute(
            should_terminate as extern "C-unwind" fn(&AnyObject, Sel, Option<&AnyObject>) -> usize,
        )
    }
}

fn register(class: &AnyClass) -> Result<(), String> {
    let selector = sel!(applicationShouldTerminate:);
    let implementation = implementation();
    if let Some(method) = class.instance_method(selector) {
        return if std::ptr::fn_addr_eq(method.implementation(), implementation) {
            Ok(())
        } else {
            Err("The native Quit delegate already has a handler.".into())
        };
    }
    let encoding = CString::new(format!("{}@:@", usize::ENCODING)).unwrap();
    // Add only the missing callback; the delegate and its other methods stay intact.
    if unsafe {
        ffi::class_addMethod(
            std::ptr::from_ref(class).cast_mut(),
            selector,
            implementation,
            encoding.as_ptr(),
        )
    }
    .as_bool()
    {
        Ok(())
    } else {
        Err("The native Quit handler could not be installed.".into())
    }
}

pub fn install(ctx: &egui::Context) -> Result<(), String> {
    let _main = MainThreadMarker::new().ok_or("The Quit handler needs the main thread.")?;
    let application = AnyClass::get(c"NSApplication").ok_or("NSApplication is unavailable.")?;
    // Cocoa owns this singleton and the Winit delegate for the application lifetime.
    unsafe {
        let app: *mut AnyObject = msg_send![application, sharedApplication];
        let delegate: *mut AnyObject = msg_send![app, delegate];
        let delegate = delegate
            .as_ref()
            .ok_or("The native application delegate is unavailable.")?;
        register(delegate.class())?;
        // Refresh AppKit's optional-method cache without replacing Winit's delegate.
        let _: () = msg_send![app, setDelegate: std::ptr::null_mut::<AnyObject>()];
        let _: () = msg_send![app, setDelegate: delegate];
    }
    CONTEXT.with(|context| *context.borrow_mut() = Some(ctx.clone()));
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use confidex_ui::{Runtime, VaultApp};
    use objc2::{rc::Retained, runtime::ClassBuilder};
    struct Host;
    impl Runtime for Host {
        fn send(&mut self, _: confidex_app::Request) -> Result<(), confidex_app::Error> {
            Ok(())
        }
        fn receive(&mut self) -> Option<confidex_app::Response> {
            None
        }
    }
    #[test]
    fn cocoa_quit_callback_defers_termination_and_requests_the_shared_close_path() {
        let class = ClassBuilder::new(
            c"ConfidexQuitDelegateTest",
            AnyClass::get(c"NSObject").unwrap(),
        )
        .unwrap()
        .register();
        register(class).unwrap();
        register(class).unwrap();
        let delegate: Retained<AnyObject> = unsafe { msg_send![class, new] };
        let ctx = egui::Context::default();
        let mut app = VaultApp::new(&ctx, Box::new(Host)).unwrap();
        CONTEXT.with(|context| *context.borrow_mut() = Some(ctx.clone()));
        let reply: usize =
            unsafe { msg_send![&*delegate, applicationShouldTerminate: None::<&AnyObject>] };
        assert_eq!(reply, 0);
        let output = ctx.run_logic(&egui::RawInput::default(), |ctx| {
            eframe::App::logic(&mut app, ctx, &mut eframe::Frame::_new_kittest());
        });
        assert!(
            output.viewport_commands[&egui::ViewportId::ROOT]
                .contains(&egui::ViewportCommand::Close)
        );
        CONTEXT.with(|context| *context.borrow_mut() = None);
    }
}
