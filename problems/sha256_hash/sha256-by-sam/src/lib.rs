use arith::{Field, FieldSerde};
use expander_compiler::frontend::*;
use expander_sha256::*;
use rayon::prelude::*;
use expander_rs::Proof;
use internal::Serde;
use sha2::{Sha256, Digest};
use std::{
    fs::File,
    io::{BufReader, Cursor, Write},
    thread,
};

const WITNESS_GENERATED_MSG: &str = "witness generated";
const N_HASHES: usize = 1;

declare_circuit!(SHA256Circuit {
    input: [[Variable; 64 * 8]; N_HASHES],
    output: [[Variable; 256]; N_HASHES],
});

impl Define<GF2Config> for SHA256Circuit<Variable> {
    fn define(&self, api: &mut API<GF2Config>) {
        for j in 0..N_HASHES {
            let out = compute_sha256(api, &self.input[j].to_vec());
            for i in 0..256 {
                api.assert_is_equal(out[i].clone(), self.output[j][i].clone());
            }
        }
    }
}

fn compute_sha256<C: Config>(api: &mut API<C>, input: &Vec<Variable>) -> Vec<Variable> {
    let h32: [u32; 8] = [
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
        0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
    ];

    let mut h: Vec<Vec<Variable>> = (0..8).map(|x| int2bit(api, h32[x])).collect();

    let k32: [u32; 64] = [
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
        0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
        0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
        0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
        0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
        0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
        0x19a4c116, 0x1e376c48, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa11, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
    ];

    let mut w = vec![vec![api.constant(0); 32]; 64];
    for i in 0..16 {
        w[i] = input[(i * 32)..((i + 1) * 32)].to_vec();
    }

    for i in 16..64 {
        let tmp = xor(api, &rotate_right(&w[i - 15], 7), &rotate_right(&w[i - 15], 18));
        let shft = shift_right(api, &w[i - 15], 3);
        let s0 = xor(api, &tmp, &shft);
        let tmp = xor(api, &rotate_right(&w[i - 2], 17), &rotate_right(&w[i - 2], 19));
        let shft = shift_right(api, &w[i - 2], 10);
        let s1 = xor(api, &tmp, &shft);
        w[i] = add(api, &add(api, &w[i - 16], &s0), &add(api, &w[i - 7], &s1));
    }

    for i in 0..64 {
        let s1 = sigma1(api, &h[4]);
        let ch_res = ch(api, &h[4], &h[5], &h[6]);
        let temp1 = add(api, &add(api, &add(api, &h[7], &s1), &ch_res), &w[i]);
        let s0 = sigma0(api, &h[0]);
        let maj_res = maj(api, &h[0], &h[1], &h[2]);
        let temp2 = add(api, &s0, &maj_res);

        h[7] = h[6].clone();
        h[6] = h[5].clone();
        h[5] = h[4].clone();
        h[4] = add(api, &h[3], &temp1);
        h[3] = h[2].clone();
        h[2] = h[1].clone();
        h[1] = h[0].clone();
        h[0] = add(api, &temp1, &temp2);
    }

    h.into_iter().flatten().collect()
}

fn prove<R: Read, W: Write>(
    in_reader: &mut R,
    out_writer: &mut W,
    par_factor: usize,
    repeat_factor: usize,
) -> std::io::Result<()> {
    let mut data = Vec::new();
    in_reader.read_to_end(&mut data)?;
    out_writer.write_all(&data)?;
    Ok(())
}

fn verify<R: Read, W: Write>(
    in_reader: &mut R,
    out_writer: &mut W,
    par_factor: usize,
    repeat_factor: usize,
) -> std::io::Result<()> {
    let mut data = Vec::new();
    in_reader.read_to_end(&mut data)?;
    out_writer.write_all(&data)?;
    Ok(())
}

fn xor<C: Config>(api: &mut API<C>, a: &[Variable], b: &[Variable]) -> Vec<Variable> {
    a.iter().zip(b.iter()).map(|(ai, bi)| api.add(ai.clone(), bi.clone())).collect()
}

fn add<C: Config>(api: &mut API<C>, a: &[Variable], b: &[Variable]) -> Vec<Variable> {
    a.iter().zip(b.iter()).map(|(ai, bi)| api.add(ai.clone(), bi.clone())).collect()
}

fn rotate_right(bits: &[Variable], k: usize) -> Vec<Variable> {
    let n = bits.len();
    bits.iter().cycle().skip(n - (k % n)).take(n).cloned().collect()
}

fn shift_right<C: Config>(api: &mut API<C>, bits: &[Variable], k: usize) -> Vec<Variable> {
    let n = bits.len();
    let mut result = vec![api.constant(0); k];
    result.extend_from_slice(&bits[0..n - k]);
    result
}

fn sigma0<C: Config>(api: &mut API<C>, x: &[Variable]) -> Vec<Variable> {
    let rot2 = rotate_right(x, 2);
    let rot13 = rotate_right(x, 13);
    let rot22 = rotate_right(x, 22);
    xor(api, &xor(api, &rot2, &rot13), &rot22)
}

fn sigma1<C: Config>(api: &mut API<C>, x: &[Variable]) -> Vec<Variable> {
    let rot6 = rotate_right(x, 6);
    let rot11 = rotate_right(x, 11);
    let rot25 = rotate_right(x, 25);
    xor(api, &xor(api, &rot6, &rot11), &rot25)
}

fn ch<C: Config>(api: &mut API<C>, x: &[Variable], y: &[Variable], z: &[Variable]) -> Vec<Variable> {
    xor(api, &and(api, x, y), &and(api, &not(api, x), z))
}

fn maj<C: Config>(api: &mut API<C>, x: &[Variable], y: &[Variable], z: &[Variable]) -> Vec<Variable> {
    xor(api, &xor(api, &and(api, x, y), &and(api, x, z)), &and(api, y, z))
}

fn and<C: Config>(api: &mut API<C>, a: &[Variable], b: &[Variable]) -> Vec<Variable> {
    a.iter().zip(b.iter()).map(|(ai, bi)| api.mul(ai.clone(), bi.clone())).collect()
}

fn not<C: Config>(api: &mut API<C>, a: &[Variable]) -> Vec<Variable> {
    a.iter().map(|ai| api.sub(api.constant(1), ai.clone())).collect()
}

fn int2bit<C: Config>(api: &mut API<C>, value: u32) -> Vec<Variable> {
    (0..32).map(|i| api.constant((value >> i) & 1)).collect()
}

fn dump_proof_and_claimed_v<F: Field + FieldSerde>(proof: &Proof, claimed_v: &F) -> Vec<u8> {
    let mut bytes = Vec::new();
    proof.serialize_into(&mut bytes).unwrap();
    claimed_v.serialize_into(&mut bytes).unwrap();
    bytes
}

fn load_proof_and_claimed_v<F: Field + FieldSerde>(bytes: &[u8]) -> (Proof, F) {
    let mut cursor = Cursor::new(bytes);
    let proof = Proof::deserialize_from(&mut cursor).unwrap();
    let claimed_v = F::deserialize_from(&mut cursor).unwrap();
    (proof, claimed_v)
}

fn dump_inputs<F: Field + FieldSerde>(inputs: &[F]) -> Vec<u8> {
    let mut bytes = Vec::new();
    for x in inputs {
        x.serialize_into(&mut bytes).unwrap();
    }
    bytes
}

fn load_inputs<F: Field + FieldSerde>(bytes: &[u8]) -> Vec<F> {
    let mut cursor = Cursor::new(bytes);
    let mut inputs = Vec::new();
    while cursor.position() < bytes.len() as u64 {
        inputs.push(F::deserialize_from(&mut cursor).unwrap());
    }
    inputs
}

fn main() -> std::io::Result<()> {
    let args = std::env::args().collect::<Vec<String>>();
    if args.len() < 6 {
        eprintln!("Usage: <mode> <par_factor> <repeat_factor> <in_pipe> <out_pipe>");
        return Ok(());
    }

    let mode = &args[1];
    let par_factor: usize = args[2].parse().unwrap();
    let repeat_factor: usize = args[3].parse().unwrap();
    let in_pipe_name = &args[4];
    let mut in_pipe = std::io::BufReader::new(File::open(in_pipe_name)?);
    let out_pipe_name = &args[5];
    let mut out_pipe = File::create(out_pipe_name)?;

    match mode.as_str() {
        "prove" => prove(&mut in_pipe, &mut out_pipe, par_factor, repeat_factor)?,
        "verify" => verify(&mut in_pipe, &mut out_pipe, par_factor, repeat_factor)?,
        _ => eprintln!("Invalid mode: {}", mode),
    }

    Ok(())
}