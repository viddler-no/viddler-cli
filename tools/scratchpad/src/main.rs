enum Enum {
    Case1,
    Case2,
    Case3,
    Case4,
    Case5(bool),
    Case6,
    Case7,
    Case8(u32),
    Case9,
    Case10,
    Case11,
    Case12,
}

fn by_enum(e: &Enum, input: &[usize]) -> usize {
    use Enum::*;
    let another = input[2];
    let another1 = input[3];
    let another2 = input[4];
    let x = another + another1 + another2;
    match e {
        Case1 => input[1],
        Case2 => input[2],
        Case3 => input[3],
        Case4 => input[4],
        Case5(_) => input[5],
        Case6 => input[6],
        Case7 => input[7],
        Case8(_) => input[8],
        Case9 => input[9],
        Case10 => input[10],
        Case11 => input[11],
        _ => x / 3,
    }
}

fn case1(input: &[usize]) -> usize {
    input[1]
}
fn case2(input: &[usize]) -> usize {
    input[2]
}
fn case3(input: &[usize]) -> usize {
    input[3]
}
fn case4(input: &[usize]) -> usize {
    input[4]
}
fn case5(input: &[usize]) -> usize {
    input[5]
}
fn case6(input: &[usize]) -> usize {
    input[6]
}
fn case7(input: &[usize]) -> usize {
    input[7]
}
fn case8(input: &[usize]) -> usize {
    input[8]
}
fn case9(input: &[usize]) -> usize {
    input[9]
}
fn case10(input: &[usize]) -> usize {
    input[10]
}
fn case11(input: &[usize]) -> usize {
    input[11]
}
fn case12(input: &[usize]) -> usize {
    input[12]
}

trait Base {
    fn handle(&self, input: &[usize]) -> usize;
}
struct T1;
impl Base for T1 {
    fn handle(&self, input: &[usize]) -> usize {
        input[1]
    }
}
struct T2;
impl Base for T2 {
    fn handle(&self, input: &[usize]) -> usize {
        input[2]
    }
}
struct T3;
impl Base for T3 {
    fn handle(&self, input: &[usize]) -> usize {
        input[3]
    }
}
struct T4;
impl Base for T4 {
    fn handle(&self, input: &[usize]) -> usize {
        input[4]
    }
}
struct T5;
impl Base for T5 {
    fn handle(&self, input: &[usize]) -> usize {
        input[5]
    }
}
struct T6;
impl Base for T6 {
    fn handle(&self, input: &[usize]) -> usize {
        input[6]
    }
}
struct T7;
impl Base for T7 {
    fn handle(&self, input: &[usize]) -> usize {
        input[7]
    }
}
struct T8;
impl Base for T8 {
    fn handle(&self, input: &[usize]) -> usize {
        input[8]
    }
}
struct T9;
impl Base for T9 {
    fn handle(&self, input: &[usize]) -> usize {
        input[9]
    }
}
struct T10;
impl Base for T10 {
    fn handle(&self, input: &[usize]) -> usize {
        input[10]
    }
}
struct T11;
impl Base for T11 {
    fn handle(&self, input: &[usize]) -> usize {
        input[11]
    }
}
struct T12;
impl Base for T12 {
    fn handle(&self, input: &[usize]) -> usize {
        input[12]
    }
}

fn main() {
    use rand::prelude::*;
    let mut input: [usize; 100] = [0; 100];
    let mut rng = rand::thread_rng();
    for i in 0..100 {
        input[i] = rng.gen();
    }
    let enums = vec![
        Enum::Case1,
        Enum::Case2,
        Enum::Case3,
        Enum::Case4,
        Enum::Case5(true),
        Enum::Case6,
        Enum::Case7,
        Enum::Case8(123),
        Enum::Case9,
        Enum::Case10,
        Enum::Case11,
        Enum::Case12,
    ];
    let mut cur = 0;
    let len = input.len() - 12;
    let before = std::time::Instant::now();
    for _i in 1..=25000 {
        for e in &enums {
            cur = by_enum(e, &input[cur..]) % len;
        }
    }
    times("Enums", before.elapsed());
    let mut fns: Vec<fn(&[usize]) -> usize> = vec![
        case1, case2, case3, case4, case5, case6, case7, case8, case9, case10, case11, case12,
    ];
    fns.push(case1);
    let before = std::time::Instant::now();
    for _i in 1..=25000 {
        for f in &fns {
            cur = f(&input[cur..]) % len;
        }
    }
    times("Funcs", before.elapsed());
    let dyns: Vec<Box<dyn Base>> = vec![
        Box::new(T1),
        Box::new(T2),
        Box::new(T3),
        Box::new(T4),
        Box::new(T5),
        Box::new(T6),
        Box::new(T7),
        Box::new(T8),
        Box::new(T9),
        Box::new(T10),
        Box::new(T11),
        Box::new(T12),
    ];
    let before = std::time::Instant::now();
    for _i in 1..=25000 {
        for d in &dyns {
            cur = d.handle(&input[cur..]) % len;
        }
    }
    times("Dynts", before.elapsed());
}

fn times(msg: &str, d: std::time::Duration) {
    println!(
        "{}: {}",
        msg,
        (d.as_secs() as f32) + (d.as_nanos() as f32) / (1_000_000_000 as f32)
    );
}

#[cfg(test)]
mod tests {
    //use test::Bencher;
}
