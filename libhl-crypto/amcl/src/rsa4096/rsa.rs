/*
Licensed to the Apache Software Foundation (ASF) under one
or more contributor license agreements.  See the NOTICE file
distributed with this work for additional information
regarding copyright ownership.  The ASF licenses this file
to you under the Apache License, Version 2.0 (the
"License"); you may not use this file except in compliance
with the License.  You may obtain a copy of the License at

  http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing,
software distributed under the License is distributed on an
"AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
KIND, either express or implied.  See the License for the
specific language governing permissions and limitations
under the License.
*/

use rsa4096::big;
use rsa4096::ff;
use rsa4096::ff::FF;

use rand::RAND;
use hash256::HASH256;
use hash384::HASH384;
use hash512::HASH512;

pub const RFS:usize =(big::MODBYTES as usize)*ff::FFLEN;
pub const SHA256:usize=32;
pub const SHA384:usize=48;
pub const SHA512:usize=64;

pub const HASH_TYPE:usize=SHA256;

pub struct RsaPrivateKey {
	p:FF,
	q:FF,
	dp:FF,
	dq:FF,
	c:FF
}

pub struct RsaPublicKey {
	e: isize,
	n: FF
}

pub fn new_private_key(n: usize) -> RsaPrivateKey {
	RsaPrivateKey {p:FF::new_int(n),q:FF::new_int(n),dp:FF::new_int(n),dq:FF::new_int(n),c:FF::new_int(n)}
}

pub fn new_public_key(m: usize) -> RsaPublicKey {
	RsaPublicKey {e:0,n:FF::new_int(m)}
}

fn hashit(sha: usize,a: Option<&[u8]>,n: isize,w: &mut [u8]) {
	if sha==SHA256 {
		let mut h=HASH256::new();
		if let Some(x)=a {
			h.process_array(x);
		}
		if n>=0 {h.process_num(n as i32)}
        let hs=h.hash();	
        for i in 0..sha {w[i]=hs[i]}
	}
	if sha==SHA384 {
		let mut h=HASH384::new();
		if let Some(x)=a {
			h.process_array(x);
		}
		if n>=0 {h.process_num(n as i32)}
        let hs=h.hash();	
        for i in 0..sha {w[i]=hs[i]}
	}
	if sha==SHA512 {
		let mut h=HASH512::new();
		if let Some(x)=a {
			h.process_array(x);
		}
		if n>=0 {h.process_num(n as i32)}
        let hs=h.hash();	
        for i in 0..sha {w[i]=hs[i]}
	}
}

pub fn key_pair(rng: &mut RAND,e: isize,prv: &mut RsaPrivateKey,pbc: &mut RsaPublicKey) { /* IEEE1363 A16.11/A16.12 more or less */
	let n=pbc.n.getlen()/2;
	let mut t=FF::new_int(n);
	let mut p1=FF::new_int(n);
	let mut q1=FF::new_int(n);

	loop {
		prv.p.random(rng);
		while prv.p.lastbits(2)!=3 {prv.p.inc(1)}		
		while !FF::prime(&prv.p,rng) {			
			prv.p.inc(4);		
		}
		
		p1.copy(&prv.p);
		p1.dec(1);

		if p1.cfactor(e) {continue}
		break;
	}

	loop {
		prv.q.random(rng);
		while prv.q.lastbits(2)!=3 {prv.q.inc(1)}
		while !FF::prime(&prv.q,rng) {
			prv.q.inc(4);
		}
			
		q1.copy(&prv.q);
		q1.dec(1);

		if q1.cfactor(e) {continue}

		break;
	}
	
	pbc.n=FF::mul(&prv.p,&prv.q);
	pbc.e=e;

	t.copy(&p1);
	t.shr();
	prv.dp.set(e);
	prv.dp.invmodp(&t);
	if prv.dp.parity()==0 {prv.dp.add(&t)}
	prv.dp.norm();

	t.copy(&q1);
	t.shr();
	prv.dq.set(e);
	prv.dq.invmodp(&t);
	if prv.dq.parity()==0 {prv.dq.add(&t)}
	prv.dq.norm();

	prv.c.copy(&prv.p);
	prv.c.invmodp(&prv.q);
}

/* Mask Generation Function */

pub fn mgf1(sha: usize,z: &[u8],olen: usize,k: &mut [u8]) {
	let hlen=sha;

	let mut j=0;
	for i in 0..k.len() {k[i]=0}

	let mut cthreshold=olen/hlen; 
	if olen%hlen!=0 {cthreshold+=1}
	for counter in 0..cthreshold {
		let mut b:[u8;64]=[0;64];		
		hashit(sha,Some(z),counter as isize,&mut b);

		if j+hlen>olen {
			for i in 0..(olen%hlen) {k[j]=b[i]; j+=1}
		} else {
			for i in 0..hlen {k[j]=b[i]; j+=1}
		}
	}	
}

/* SHAXXX identifier strings */
const SHA256ID:[u8;19]= [0x30,0x31,0x30,0x0d,0x06,0x09,0x60,0x86,0x48,0x01,0x65,0x03,0x04,0x02,0x01,0x05,0x00,0x04,0x20];
const SHA384ID:[u8;19]= [0x30,0x41,0x30,0x0d,0x06,0x09,0x60,0x86,0x48,0x01,0x65,0x03,0x04,0x02,0x02,0x05,0x00,0x04,0x30];
const SHA512ID:[u8;19]= [0x30,0x51,0x30,0x0d,0x06,0x09,0x60,0x86,0x48,0x01,0x65,0x03,0x04,0x02,0x03,0x05,0x00,0x04,0x40];

pub fn pkcs15(sha: usize,m: &[u8],w: &mut [u8]) -> bool {
	let olen=ff::FF_BITS/8;
	let hlen=sha;
	let idlen=19;
	let mut b:[u8;64]=[0;64];  /* Not good */	

	if olen<idlen+hlen+10 {return false}
	hashit(sha,Some(m),-1,&mut b);

	for i in 0..w.len() {w[i]=0}
	let mut i=0;
	w[i]=0; i+=1;
	w[i]=1; i+=1;
	for _ in 0..olen-idlen-hlen-3 {w[i]=0xff; i+=1}
	w[i]=0; i+=1;

	if hlen==SHA256 {
		for j in 0..idlen {w[i]=SHA256ID[j]; i+=1}
	}
	if hlen==SHA384 {
		for j in 0..idlen {w[i]=SHA384ID[j]; i+=1}
	}
	if hlen==SHA512 {
		for j in 0..idlen {w[i]=SHA512ID[j]; i+=1}
	}
	for j in 0..hlen {w[i]=b[j]; i+=1}

	return true;
}

/* OAEP Message Encoding for Encryption */
pub fn oaep_encode(sha: usize,m: &[u8],rng: &mut RAND,p: Option<&[u8]>,f: &mut [u8]) -> bool { 
	let olen=RFS-1;
	let mlen=m.len();

	let hlen=sha;

	let mut seed:[u8;64]=[0;64];

	let seedlen=hlen;
	if mlen>olen-hlen-seedlen-1 {return false} 

	let mut dbmask:[u8;RFS]=[0;RFS];

	hashit(sha,p,-1,f);
	let slen=olen-mlen-hlen-seedlen-1;      

	for i in 0..slen {f[hlen+i]=0}
	f[hlen+slen]=1;
	for i in 0..mlen {f[hlen+slen+1+i]=m[i]}

	for i in 0..seedlen {seed[i]=rng.getbyte()}
	
	mgf1(sha,&seed,olen-seedlen,&mut dbmask);

	for i in 0..olen-seedlen {dbmask[i]^=f[i]}

	mgf1(sha,&dbmask[0..olen-seedlen],seedlen,f);

	for i in 0..seedlen {f[i]^=seed[i]}

	for i in 0..olen-seedlen {f[i+seedlen]=dbmask[i]}

	/* pad to length RFS */
	let d=1;
	for i in (d..RFS).rev() {
		f[i]=f[i-d];
	}
	for i in (0..d).rev() {
		f[i]=0;
	}
	return true;
}

/* OAEP Message Decoding for Decryption */
pub fn oaep_decode(sha: usize,p: Option<&[u8]>,f: &mut [u8]) -> usize {
	let olen=RFS-1;

	let hlen=sha;
	let mut seed:[u8;64]=[0;64];
	let seedlen=hlen;
	let mut chash:[u8;64]=[0;64];
	
	if olen<seedlen+hlen+1 {return 0}
	let mut dbmask:[u8;RFS]=[0;RFS];
	//for i in 0..olen-seedlen {dbmask[i]=0}

	if f.len()<RFS {
		let d=RFS-f.len();
		for i in (d..RFS).rev() {
			f[i]=f[i-d];
		}
		for i in (0..d).rev() {
			f[i]=0;
		}
	}

	hashit(sha,p,-1,&mut chash);

	let x=f[0];

	for i in seedlen..olen {
		dbmask[i-seedlen]=f[i+1];
	}

	mgf1(sha,&dbmask[0..olen-seedlen],seedlen,&mut seed);
	for i in 0..seedlen {seed[i]^=f[i+1]}
	mgf1(sha,&seed,olen-seedlen,f);
	for i in 0..olen-seedlen {dbmask[i]^=f[i]}

	let mut comp=true;
	for i in 0..hlen {
		if chash[i]!=dbmask[i] {comp=false}
	}

	for i in 0..olen-seedlen-hlen {
		dbmask[i]=dbmask[i+hlen]
	}

	for i in 0..hlen {
		seed[i]=0; chash[i]=0
	}
		
	let mut k=0;
	loop {
		if k>=olen-seedlen-hlen {return 0}
		if dbmask[k]!=0 {break}
		k+=1;
	}

	let t=dbmask[k];
	if !comp || x!=0 || t!=0x01 {
		for i in 0..olen-seedlen {dbmask[i]=0}
		return 0;
	}

	for i in 0..olen-seedlen-hlen-k-1 {
		f[i]=dbmask[i+k+1];
	}
	
	for i in 0..olen-seedlen  {dbmask[i]=0}

	return olen-seedlen-hlen-k-1;
}

/* destroy the Private Key structure */
pub fn private_key_kill(prv: &mut RsaPrivateKey) {
	prv.p.zero();
	prv.q.zero();
	prv.dp.zero();
	prv.dq.zero();
	prv.c.zero();
}

/* RSA encryption with the public key */
pub fn encrypt(pbc: &RsaPublicKey,f: &[u8],g: &mut [u8]) {
	let m=pbc.n.getlen();
	let mut r=FF::new_int(m);

	FF::frombytes(&mut r,f);
	r.power(pbc.e,&pbc.n);
	r.tobytes(g);
}

/* RSA decryption with the private key */
pub fn decrypt(prv: &RsaPrivateKey,g: &[u8],f: &mut [u8]) {
	let n=prv.p.getlen();
	let mut r=FF::new_int(2*n);

	FF::frombytes(&mut r,g);
	let mut jp=r.dmod(&prv.p);
	let mut jq=r.dmod(&prv.q);

	jp.skpow(&prv.dp,&prv.p);
	jq.skpow(&prv.dq,&prv.q);

	r.zero();
	r.dscopy(&jp);
	jp.rmod(&prv.q);
	if FF::comp(&jp,&jq)>0 {jq.add(&prv.q)}
	jq.sub(&jp);
	jq.norm();

	let mut t=FF::mul(&prv.c,&jq);
	jq=t.dmod(&prv.q);

	t=FF::mul(&jq,&prv.p);
	r.add(&t);
	r.norm();

	r.tobytes(f);
}

