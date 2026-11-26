use crate::BrowserStore;
use confidex_app::{DeviceKeys, Engine, Request, Response, sync::Transport};

pub struct Runtime<T> {
    engine: Engine,
    store: BrowserStore,
    transport: T,
}

impl<T> Runtime<T> {
    pub fn new(transport: T) -> Self {
        Self {
            engine: Engine::default(),
            store: BrowserStore,
            transport,
        }
    }

    pub fn engine_mut(&mut self) -> &mut Engine {
        &mut self.engine
    }
}

impl<T: Default> Default for Runtime<T> {
    fn default() -> Self {
        Self::new(T::default())
    }
}

impl<T: Transport> Runtime<T> {
    pub async fn execute(&mut self, keys: &mut impl DeviceKeys, request: &mut Request) -> Response {
        self.engine
            .execute_with_transport(&mut self.store, keys, &mut self.transport, request)
            .await
    }
}
