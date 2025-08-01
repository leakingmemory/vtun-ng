use crate::{mainvtun};
use crate::filedes::FileDes;

pub trait Driver {
    fn write(&self, buf: &[u8]) -> Option<usize>;
    fn read(&self, buf: &mut Vec<u8>, len: usize) -> bool;
    fn io_fd(&self) -> Option<&FileDes>;
    fn detach(&mut self) -> FileDes {
        FileDes::new()
    }
    fn close_first_pipe_fd(&mut self) {
    }
    fn clone_second_pipe_fd(&self) -> FileDes {
        FileDes::new()
    }
    fn close_second_pipe_fd(&mut self) {
    }
}

pub trait NetworkDriver {
    fn io_fd(&self) -> &FileDes;
    fn write(&self, buf: &mut Vec<u8>, flags: u16) -> Option<usize>;
    fn read(&mut self, ctx: &mut mainvtun::VtunContext, buf: &mut Vec<u8>) -> Option<u16>;
}
