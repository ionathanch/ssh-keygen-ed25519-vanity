extern crate rand;
extern crate regex;
extern crate base64;
extern crate bytebuffer;
extern crate ed25519_dalek;

use std::env::args;
use std::mem::size_of;
use std::error::Error;
use std::io::Write;
use std::path::Path;
use std::fs::{File, Permissions};
use std::os::unix::fs::PermissionsExt;

use rand::rngs::OsRng;
use regex::Regex;
use base64::{Engine, engine::general_purpose};
use bytebuffer::{ByteBuffer, Endian::BigEndian};
use ed25519_dalek::{Keypair, PUBLIC_KEY_LENGTH, SECRET_KEY_LENGTH};

const KEYTYPE: &[u8] = b"ssh-ed25519";
const MAGIC: &[u8] = b"openssh-key-v1\x00";
const NONE: &[u8] = b"none";
const BLOCKSIZE: usize = 8;
const CHECK: u32 = 0xf0cacc1a;

fn get_sk(pk: &[u8], keypair: Keypair) -> String {
  let mut buffer = ByteBuffer::new();
  buffer.write_bytes(MAGIC);
  buffer.write_u32(NONE.len() as u32);
  buffer.write_bytes(NONE);                   // cipher
  buffer.write_u32(NONE.len() as u32);
  buffer.write_bytes(NONE);                   // kdfname
  buffer.write_u32(0);                        // no kdfoptions
  buffer.write_u32(1);                        // public keys
  buffer.write_u32(pk.len() as u32);
  buffer.write_bytes(pk);                     // public key

  let mut sk = ByteBuffer::new();
  sk.write_u32(CHECK);                        // check bytes
  sk.write_u32(CHECK);
  sk.write_bytes(pk);                         // public key (again)
  sk.write_u32((SECRET_KEY_LENGTH + PUBLIC_KEY_LENGTH) as u32);
  sk.write_bytes(&keypair.secret.to_bytes()); // private key
  sk.write_bytes(&keypair.public.to_bytes()); // public part of private key
  sk.write_u32(0);                            // no comments
  for p in 1..=(buffer.len() + sk.len() + size_of::<u32>()) % BLOCKSIZE {
    sk.write_u8(p as u8);                     // padding
  }

  buffer.write_u32(sk.len() as u32);
  buffer.write_bytes(&sk.as_bytes());
  return general_purpose::STANDARD.encode(buffer.as_bytes());
}

fn main() -> Result<(), Box<dyn Error>> {
  let pattern = args().nth(1).unwrap_or_default();
  let path = args().nth(2);
  let regex = Regex::new(&pattern)?;
  let mut csprng = OsRng{};
  let mut buffer = ByteBuffer::new();
  buffer.set_endian(BigEndian);
  buffer.write_u32(KEYTYPE.len() as u32);
  buffer.write_bytes(KEYTYPE);
  buffer.write_u32(PUBLIC_KEY_LENGTH as u32);

  loop {
    let keypair = Keypair::generate(&mut csprng);
    buffer.write_bytes(&keypair.public.to_bytes());
    let pk = buffer.as_bytes();
    let pk64 = general_purpose::STANDARD.encode(&pk);
    if regex.is_match(&pk64) {
      println!("ssh-ed25519 {}", pk64);
      let sk64 = get_sk(&pk, keypair);
      match path {
        Some(path) => {
          let mut public = File::create(Path::new(&path).with_extension("pub"))?;
          if cfg!(unix) {
            public.set_permissions(Permissions::from_mode(0o644))?;
          }
          writeln!(public, "ssh-ed25519 {}", pk64)?;

          let mut private = File::create(path)?;
          if cfg!(unix) {
            private.set_permissions(Permissions::from_mode(0o600))?;
          }
          writeln!(private, "-----BEGIN OPENSSH PRIVATE KEY-----")?;
          writeln!(private, "{}", sk64)?;
          writeln!(private, "-----END OPENSSH PRIVATE KEY-----")?;
        }
        None => {
          println!("-----BEGIN OPENSSH PRIVATE KEY-----");
          println!("{}", sk64);
          println!("-----END OPENSSH PRIVATE KEY-----");
        }
      }
      break Ok(());
    }
    buffer.set_wpos(buffer.get_wpos() - PUBLIC_KEY_LENGTH);
  }
}
