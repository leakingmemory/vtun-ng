pub trait Driver {
    fn write(&self, buf: &[u8]) -> Option<usize>;
    fn read(&self, buf: &mut Vec<u8>, len: usize) -> bool;
    fn io_fd(&self) -> i32;
    fn detach(&mut self) -> i32 {
        -1
    }
    fn close_first_pipe_fd(&mut self) {
    }
    fn second_pipe_fd(&self) -> i32 {
        -1
    }
    fn close_second_pipe_fd(&mut self) {
    }
}

pub trait NetworkDriver {
    fn write(&self, buf: &mut Vec<u8>, flags: u16) -> Option<usize>;
    fn read(&mut self, buf: &mut Vec<u8>) -> Option<u16>;
}
