use std::sync::{Arc, OnceLock};

use crate::{
    InjectedProcess, InjectedProgram, Library, Process, Program, Result, SuspendedProgram,
};

mod frida;

#[derive(Clone)]
pub(crate) struct BackendHandle {
    inner: Arc<frida::FridaBackend>,
}

impl std::fmt::Debug for BackendHandle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("BackendHandle(..)")
    }
}

impl BackendHandle {
    fn new(inner: frida::FridaBackend) -> Self {
        Self {
            inner: Arc::new(inner),
        }
    }

    pub(crate) fn uninject(&self, id: u64) -> Result<()> {
        self.inner.uninject(id)
    }

    pub(crate) fn inject_program(
        &self,
        mut spec: Program,
        library: Library,
    ) -> Result<InjectedProgram> {
        let stdio = spec.stdio_value();
        let (process, id) = self.inner.inject_launch(&mut spec, &library)?;
        let child = crate::Child::new(process, stdio);
        Ok(InjectedProgram::new(self.clone(), id, process, child))
    }

    pub(crate) fn inject_process(
        &self,
        process: Process,
        library: Library,
    ) -> Result<InjectedProcess> {
        let id = self.inner.inject_process(process, &library)?;
        Ok(InjectedProcess::new(self.clone(), id, process))
    }

    pub(crate) fn spawn(&self, mut spec: Program) -> Result<crate::SuspendedProgram> {
        let stdio = spec.stdio_value();
        self.inner
            .spawn(&mut spec)
            .map(|process| SuspendedProgram::new(self.clone(), process, stdio))
    }

    pub(crate) fn resume(&self, process: Process) -> Result<()> {
        self.inner.resume(process)
    }
}

static BACKEND: OnceLock<Result<BackendHandle>> = OnceLock::new();

pub(crate) fn default_backend() -> Result<BackendHandle> {
    if let Some(existing) = BACKEND.get() {
        return existing.clone();
    }

    let handle = frida::init().map(BackendHandle::new);

    let _ = BACKEND.set(handle.clone());
    handle
}
