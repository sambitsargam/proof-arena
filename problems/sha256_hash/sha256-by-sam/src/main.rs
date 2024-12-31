use expander_compiler::frontend::*;
mod spj;
pub use spj::*;

pub fn int2bit<C: Config>(api: &mut API<C>, value: u32) -> Vec<Variable> {
    (0..32).map(|x| api.constant(((value >> x) & 1) as u32)).collect()
}

pub fn rotate_right(bits: &[Variable], k: usize) -> Vec<Variable> {
    let n = bits.len();
    let s = k % n;
    bits.iter().cycle().skip(n - s).take(n).cloned().collect()
}

pub fn shift_right<C: Config>(api: &mut API<C>, bits: Vec<Variable>, k: usize) -> Vec<Variable> {
    let n = bits.len();
    let s = k % n;
    let mut new_bits = vec![api.constant(0); s];
    new_bits.extend_from_slice(&bits[0..n - s]);
    new_bits
}

pub fn ch<C: Config>(api: &mut API<C>, x: Vec<Variable>, y: Vec<Variable>, z: Vec<Variable>) -> Vec<Variable> {
    let xy = and(api, &x, &y);
    let not_x = not(api, &x);
    let not_xz = and(api, &not_x, &z);
    
    xor(api, &xy, &not_xz)
}

pub fn maj<C: Config>(api: &mut API<C>, x: Vec<Variable>, y: Vec<Variable>, z: Vec<Variable>) -> Vec<Variable> {
    let xy = and(api, &x, &y);
    let xz = and(api, &x, &z);
    let yz = and(api, &y, &z);
    let tmp = xor(api, &xy, &xz);

    xor(api, &tmp, &yz)
}

pub fn sigma0<C: Config>(api: &mut API<C>, x: Vec<Variable>) -> Vec<Variable> {
    let rot2 = rotate_right(&x, 2);
    let rot13 = rotate_right(&x, 13);
    let rot22 = rotate_right(&x, 22);
    let tmp = xor(api, &rot2, &rot13);

    xor(api, &tmp, &rot22)
}

pub fn sigma1<C: Config>(api: &mut API<C>, x: Vec<Variable>) -> Vec<Variable> {
    let rot6 = rotate_right(&x, 6);
    let rot11 = rotate_right(&x, 11);
    let rot25 = rotate_right(&x, 25);
    let tmp = xor(api, &rot6, &rot11);

    xor(api, &tmp, &rot25)
}

pub fn add<C: Config>(api: &mut API<C>, a: Vec<Variable>, b: Vec<Variable>) -> Vec<Variable> {
    add_brentkung(api, &a, &b)
}

pub fn add_brentkung<C: Config>(api: &mut API<C>, a: &[Variable], b: &[Variable]) -> Vec<Variable> {
    let mut c = vec![api.constant(0); 32];
    let mut ci = api.constant(0);

    for i in 0..8 {
        let start = i * 4;
        let end = std::cmp::min(start + 4, 32);
        let (sum, new_ci) = brent_kung_adder_4_bits(api, &a[start..end], &b[start..end], ci.clone());
        c[start..end].copy_from_slice(&sum);
        ci = new_ci;
    }

    c
}

fn brent_kung_adder_4_bits<C: Config>(api: &mut API<C>, a: &[Variable], b: &[Variable], carry_in: Variable) -> ([Variable; 4], Variable) {
    let mut g = [api.constant(0); 4];
    let mut p = [api.constant(0); 4];

    for i in 0..4 {
        g[i] = api.mul(a[i].clone(), b[i].clone());
        p[i] = api.add(a[i].clone(), b[i].clone());
    }

    let g10 = api.add(g[1].clone(), api.mul(p[1].clone(), g[0].clone()));
    let g20 = api.add(g[2].clone(), api.mul(p[2].clone(), g10.clone()));
    let g30 = api.add(g[3].clone(), api.mul(p[3].clone(), g20.clone()));

    let c1 = api.add(g[0].clone(), api.mul(p[0].clone(), carry_in.clone()));
    let c2 = api.add(g10, api.mul(p[0].clone(), c1.clone()));
    let c3 = api.add(g20, api.mul(p[0].clone(), c2.clone()));
    let c4 = api.add(g30, api.mul(p[0].clone(), c3.clone()));

    let sums = [
        api.add(p[0].clone(), carry_in),
        api.add(p[1].clone(), c1),
        api.add(p[2].clone(), c2),
        api.add(p[3].clone(), c3),
    ];

    (sums, c4)
}

pub fn xor<C: Config>(api: &mut API<C>, a: &[Variable], b: &[Variable]) -> Vec<Variable> {
    a.iter().zip(b.iter()).map(|(ai, bi)| api.add(ai.clone(), bi.clone())).collect()
}

pub fn and<C: Config>(api: &mut API<C>, a: &[Variable], b: &[Variable]) -> Vec<Variable> {
    a.iter().zip(b.iter()).map(|(ai, bi)| api.mul(ai.clone(), bi.clone())).collect()
}

pub fn not<C: Config>(api: &mut API<C>, a: &[Variable]) -> Vec<Variable> {
    a.iter().map(|ai| api.sub(1, ai.clone())).collect()
}

pub fn add_const<C: Config>(api: &mut API<C>, a: Vec<Variable>, b: u32) -> Vec<Variable> {
    let mut c = Vec::with_capacity(a.len());
    let mut ci = api.constant(0);

    for (i, val) in a.iter().enumerate() {
        if (b >> i) & 1 == 1 {
            let p = api.add(val.clone(), 1);
            c.push(api.add(p.clone(), ci.clone()));
            ci = api.mul(ci, p);
            ci = api.add(ci, val.clone());
        } else {
            c.push(api.add(val.clone(), ci.clone()));
            ci = api.mul(ci, val.clone());
        }
    }
    c
}