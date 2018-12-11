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

use bls381::ecp;
use bls381::ecp::ECP;
use bls381::big::BIG;
use bls381::rom;
use bls381::big;

use rand::RAND;
use hash256::HASH256;
use hash384::HASH384;
use hash512::HASH512;
use aes;
use aes::AES;


pub const INVALID_PUBLIC_KEY:isize=-2;
pub const ERROR:  isize=-3;
pub const INVALID: isize=-4;
pub const EFS: usize=big::MODBYTES as usize;
pub const EGS: usize=big::MODBYTES as usize;
//pub const EAS: usize=16;
//pub const EBS: usize=16;
pub const SHA256: usize=32;
pub const SHA384: usize=48;
pub const SHA512: usize=64;

//pub const HASH_TYPE: usize=SHA512;

#[allow(non_snake_case)]

fn inttobytes(n: usize,b:&mut [u8]) {
	let mut i=b.len();
	let mut m=n;
	while m>0 && i>0 {
		i-=1;
		b[i]=(m&0xff) as u8;
		m/=256;
	}	
}

fn hashit(sha: usize, a: &[u8],n: usize,b: Option<&[u8]>,pad: usize,w: &mut [u8])  {
	let mut r:[u8;64]=[0;64];
	if sha==SHA256 {
		let mut h=HASH256::new();
		h.process_array(a);
		if n>0 {h.process_num(n as i32)}
		if let Some(x) = b {
			h.process_array(x);
        }
        let hs=h.hash();	
        for i in 0..sha {r[i]=hs[i];}	
	}
	if sha==SHA384 {
		let mut h=HASH384::new();
		h.process_array(a);
		if n>0 {h.process_num(n as i32)}		
		if let Some(x) = b {
			h.process_array(x);
        }
        let hs=h.hash();	
        for i in 0..sha {r[i]=hs[i];}	        
	}
	if sha==SHA512 {
		let mut h=HASH512::new();
		h.process_array(a);
		if n>0 {h.process_num(n as i32)}
		if let Some(x) = b {
			h.process_array(x);
        }
        let hs=h.hash();
        for i in 0..sha {r[i]=hs[i];}	        	
	}

	if pad==0 {
		for i in 0..sha {w[i]=r[i]}
	} else {

		if pad<=sha {
			for i in 0..pad {w[i]=r[i]}
		} else {
			for i in 0..sha {w[i+pad-sha]=r[i]}
			for i in 0..(pad-sha) {w[i]=0}
 

			//for i in 0..sha {w[i]=r[i]}
			//for i in sha..pad {w[i]=0}
		}
	}
}

/* Key Derivation Functions */
/* Input octet Z */
/* Output key of length olen */
pub fn kdf1(sha: usize,z: &[u8],olen: usize,k: &mut [u8])  {
/* NOTE: the parameter olen is the length of the output K in bytes */
	let hlen=sha;
	let mut lk=0;

	let mut cthreshold=olen/hlen; if olen%hlen!=0 {cthreshold+=1}

	for counter in 0..cthreshold {
		let mut b:[u8;64]=[0;64];
		hashit(sha,z,counter,None,0,&mut b);
		if lk+hlen>olen {
			for i in 0..(olen%hlen) {k[lk]=b[i]; lk+=1}
		} else {
			for i in 0..hlen {k[lk]=b[i]; lk+=1}
		}
	}
}

pub fn kdf2(sha: usize,z: &[u8],p: Option<&[u8]>,olen: usize,k: &mut [u8])  {
/* NOTE: the parameter olen is the length of the output K in bytes */
	let hlen=sha;
	let mut lk=0;

	let mut cthreshold=olen/hlen; if olen%hlen!=0 {cthreshold+=1}

	for counter in 1..cthreshold+1 {
		let mut b:[u8;64]=[0;64];
		hashit(sha,z,counter,p,0,&mut b);
		if lk+hlen>olen {
			for i in 0..(olen%hlen) {k[lk]=b[i]; lk+=1}
		} else {
			for i in 0..hlen {k[lk]=b[i]; lk+=1}
		}
	}
}

/* Password based Key Derivation Function */
/* Input password p, salt s, and repeat count */
/* Output key of length olen */
pub fn pbkdf2(sha: usize,pass: &[u8],salt: &[u8],rep: usize,olen: usize,k: &mut [u8]) {
	let mut d=olen/sha; if olen%sha!=0 {d+=1}
	let mut f:[u8;64]=[0;64];
	let mut u:[u8;64]=[0;64];
	let mut ku:[u8;64]=[0;64];	
	let mut s:[u8;36]=[0;36];    // Maximum salt of 32 bytes + 4
	let mut n:[u8;4]=[0;4];

	let sl=salt.len();
	let mut kp=0;
	for i in 0..d {
		for j in 0..sl {s[j]=salt[j]} 
		inttobytes(i+1,&mut n);
		for j in 0..4 {s[sl+j]=n[j]}   

		hmac(sha,&s[0..sl+4],pass,sha,&mut f);

		for j in 0..sha {u[j]=f[j]}
		for _ in 1..rep {
			hmac(sha,&mut u,pass,sha,&mut ku);
			for k in 0..sha {u[k]=ku[k]; f[k]^=u[k]}
		}
		for j in 0..EFS {if kp<olen {k[kp]=f[j]} kp+=1} 
	}
}

/* Calculate HMAC of m using key k. HMAC is tag of length olen (which is length of tag) */
pub fn hmac(sha: usize,m: &[u8],k: &[u8],olen: usize,tag: &mut [u8]) -> bool {
	/* Input is from an octet m        *
	* olen is requested output length in bytes. k is the key  *
	* The output is the calculated tag */
	let mut b:[u8;64]=[0;64];  /* Not good */
	let mut k0:[u8;128]=[0;128];
//	let olen=tag.len();    /* length of HMAC */

	if olen<4 /*|| olen>sha */ {return false}

	let mut lb=64;
	if sha>32 {lb=128}

	for i in 0..lb {k0[i]=0}

	if k.len() > lb {
		hashit(sha,k,0,None,0,&mut b); 
		for i in 0..sha {k0[i]=b[i]}
	} else {
		for i in 0..k.len()  {k0[i]=k[i]}
	}
		
	for i in 0..lb {k0[i]^=0x36}
	hashit(sha,&mut k0[0..lb],0,Some(m),0,&mut b);

	for i in 0..lb {k0[i]^=0x6a}
	hashit(sha,&mut k0[0..lb],0,Some(&b[0..sha]),olen,tag); 

	return true;
}

/* AES encryption/decryption. Encrypt byte array m using key k and returns ciphertext c */
pub fn cbc_iv0_encrypt(k: &[u8],m: &[u8]) -> Vec<u8> { /* AES CBC encryption, with Null IV and key K */
	/* Input is from an octet string m, output is to an octet string c */
	/* Input is padded as necessary to make up a full final block */
	let mut a=AES::new();	
	let mut fin=false;
	let mut c:Vec<u8>=Vec::new();

	let mut buff:[u8;16]=[0;16];

	a.init(aes::CBC,k.len(),k,None);

	let mut ipt=0; 
//	let mut opt=0;
	let mut i;
	loop {
		i=0;
		while i<16 {
			if ipt<m.len() {
				buff[i]=m[ipt]; i+=1; ipt+=1;
			} else {fin=true; break;}
		}
		if fin {break}
		a.encrypt(&mut buff);
		for j in 0..16 {
			c.push(buff[j]);
			//c[opt]=buff[j]; opt+=1;
		}
	}    

/* last block, filled up to i-th index */

	let padlen=16-i;
	for j in i..16 {buff[j]=padlen as u8}

	a.encrypt(&mut buff);

	for j in 0..16 {
		c.push(buff[j]);
		//c[opt]=buff[j]; opt+=1;
	}
	a.end();   
	return c;
}

/* returns plaintext if all consistent, else returns null string */
pub fn cbc_iv0_decrypt(k: &[u8],c: &[u8]) -> Option<Vec<u8>> { /* padding is removed */
	let mut a=AES::new();	
	let mut fin=false;
	let mut m:Vec<u8>=Vec::new();

	let mut buff:[u8;16]=[0;16];

	a.init(aes::CBC,k.len(),k,None);

	let mut ipt=0; 
	//let mut opt=0;
	let mut i;

	if c.len()==0 {return None}
	let mut ch=c[ipt]; ipt+=1;

	loop {
		i=0;
		while i<16 {
			buff[i]=ch;    
			if ipt>=c.len() {
				fin=true; break;
			}  else {ch=c[ipt]; ipt+=1 }
			i+=1;
		}
		a.decrypt(&mut buff);
		if fin {break}
		for j in 0..16 {
			m.push(buff[j]);
			//m[opt]=buff[j]; opt+=1;
		}
	}    

	a.end();
	let mut bad=false;
	let padlen=buff[15] as usize;
	if i!=15 || padlen<1 || padlen>16 {bad=true}
	if padlen>=2 && padlen<=16 {
		for j in 16-padlen..16 {
			if buff[j]!=padlen as u8 {bad=true}
		}
	}
    
	if !bad { 
		for _ in 0..16-padlen {
			m.push(buff[i]);
			//m[opt]=buff[j]; opt+=1;
		}
	}

	if bad {return None}
	return Some(m);
}

/* Calculate a public/private EC GF(p) key pair w,s where W=s.G mod EC(p),
 * where s is the secret key and W is the public key
 * and G is fixed generator.
 * If RNG is NULL then the private key is provided externally in s
 * otherwise it is generated randomly internally */
 #[allow(non_snake_case)]
pub fn key_pair_generate(rng: Option<&mut RAND>,s: &mut [u8],w: &mut [u8]) -> isize {
	let res=0;
	let mut sc:BIG;
	let G=ECP::generator();

	let r=BIG::new_ints(&rom::CURVE_ORDER);

	if let Some(mut x)=rng {
		sc=BIG::randomnum(&r,&mut x);
	} else {
		sc=BIG::frombytes(&s);
		sc.rmod(&r);		
	}

	//if rom::AES_S>0 {
	//	sc.mod2m(2*rom::AES_S)
	//}
	sc.tobytes(s);

	let mut WP=G.mul(&mut sc);

	WP.tobytes(w,false);   // To use point compression on public keys, change to true 

	return res;
}

/* validate public key */
#[allow(non_snake_case)]
pub fn public_key_validate(w: &[u8]) -> isize {
	let mut WP=ECP::frombytes(w);
	let mut res=0;

	let r=BIG::new_ints(&rom::CURVE_ORDER);

	if WP.is_infinity() {res=INVALID_PUBLIC_KEY}
	if res==0  {

		let q=BIG::new_ints(&rom::MODULUS);
		let nb=q.nbits();
		let mut k=BIG::new(); k.one(); k.shl((nb+4)/2);
		k.add(&q);
		k.div(&r);

		while k.parity()==0 {
				k.shr(1);
				WP.dbl();
		}

		if !k.isunity() {WP=WP.mul(&mut k)}
		if WP.is_infinity() {res=INVALID_PUBLIC_KEY} 		

	}
	return res;
}

/* IEEE-1363 Diffie-Hellman online calculation Z=S.WD */
#[allow(non_snake_case)]
pub fn ecpsvdp_dh(s: &[u8],wd: &[u8],z: &mut [u8]) -> isize {
	let mut res=0;
	let mut t:[u8;EFS]=[0;EFS];

	let mut sc=BIG::frombytes(&s);

	let mut W=ECP::frombytes(&wd);
	if W.is_infinity() {res=ERROR}

	if res==0 {
		let r=BIG::new_ints(&rom::CURVE_ORDER);
		sc.rmod(&r);
		W=W.mul(&mut sc);
		if W.is_infinity() { 
			res=ERROR;
		} else {
			W.getx().tobytes(&mut t);
			for i in 0..EFS {z[i]=t[i]}
		}
	}
	return res;
}

/* IEEE ECDSA Signature, C and D are signature on F using private key S */
#[allow(non_snake_case)]
pub fn ecpsp_dsa(sha: usize,rng: &mut RAND,s: &[u8],f: &[u8],c: &mut [u8],d: &mut [u8]) -> isize {
	let mut t:[u8;EFS]=[0;EFS];
	let mut b:[u8;big::MODBYTES as usize]=[0;big::MODBYTES as usize];

	hashit(sha,f,0,None,big::MODBYTES as usize,&mut b);

	let G=ECP::generator();


	let r=BIG::new_ints(&rom::CURVE_ORDER);

	let mut sc=BIG::frombytes(s);  /* s or &s? */
	let fb=BIG::frombytes(&b);

	let mut cb=BIG::new();
	let mut db=BIG::new();
	let mut tb=BIG::new();	
	let mut V=ECP::new();

	while db.iszilch() {
		let mut u=BIG::randomnum(&r,rng);
		let mut w=BIG::randomnum(&r,rng);   /* side channel masking */
		//if rom::AES_S>0 {
		//	u.mod2m(2*rom::AES_S);
		//}			
		V.copy(&G);
		V=V.mul(&mut u);   		
		let vx=V.getx();
		cb.copy(&vx);
		cb.rmod(&r);
		if cb.iszilch() {continue}

		tb.copy(&BIG::modmul(&mut u,&mut w,&r));
		u.copy(&tb);

		u.invmodp(&r);
		db.copy(&BIG::modmul(&mut sc,&mut cb,&r));
		db.add(&fb);

		tb.copy(&BIG::modmul(&mut db,&mut w,&r));
		db.copy(&tb);

		tb.copy(&BIG::modmul(&mut u,&mut db,&r));
		db.copy(&tb);
	} 
       
	cb.tobytes(&mut t);
	for i in 0..EFS {c[i]=t[i]}
	db.tobytes(&mut t);
	for i in 0..EFS {d[i]=t[i]}
	return 0;
}

/* IEEE1363 ECDSA Signature Verification. Signature C and D on F is verified using public key W */
#[allow(non_snake_case)]
pub fn ecpvp_dsa(sha: usize,w: &[u8],f: &[u8],c: &[u8],d: &[u8]) -> isize {
	let mut res=0;

	let mut b:[u8;big::MODBYTES as usize]=[0;big::MODBYTES as usize];

	hashit(sha,f,0,None,big::MODBYTES as usize,&mut b);

	let mut G=ECP::generator();

	let r=BIG::new_ints(&rom::CURVE_ORDER);

	let mut cb=BIG::frombytes(c);  /* c or &c ? */
	let mut db=BIG::frombytes(d);  /* d or &d ? */
	let mut fb=BIG::frombytes(&b);
	let mut tb=BIG::new();		
     
	if cb.iszilch() || BIG::comp(&cb,&r)>=0 || db.iszilch() || BIG::comp(&db,&r)>=0 {
            res=INVALID;
	}

	if res==0 {
		db.invmodp(&r);
		tb.copy(&BIG::modmul(&mut fb,&mut db,&r));
		fb.copy(&tb);
		let h2=BIG::modmul(&mut cb,&mut db,&r);

		let WP=ECP::frombytes(&w);
		if WP.is_infinity() {
			res=ERROR;
		} else {
			let mut P=ECP::new();
			P.copy(&WP);

			P=P.mul2(&h2,&mut G,&fb);

			if P.is_infinity() {
				res=INVALID;
			} else {
				db=P.getx();
				db.rmod(&r);

				if BIG::comp(&db,&cb)!=0 {res=INVALID}
			}
		}
	}

	return res;
}

/* IEEE1363 ECIES encryption. Encryption of plaintext M uses public key W and produces ciphertext V,C,T */
#[allow(non_snake_case)]
pub fn ecies_encrypt(sha: usize,p1: &[u8],p2: &[u8],rng: &mut RAND,w: &[u8],m: &[u8],v: &mut [u8],t: &mut [u8]) -> Option<Vec<u8>> { 
	let mut z:[u8;EFS]=[0;EFS];
	let mut k1:[u8;ecp::AESKEY]=[0;ecp::AESKEY];
	let mut k2:[u8;ecp::AESKEY]=[0;ecp::AESKEY];
	let mut u:[u8;EGS]=[0;EGS];
	let mut vz:[u8;3*EFS+1]=[0;3*EFS+1];	
	let mut k:[u8;2*ecp::AESKEY]=[0;2*ecp::AESKEY];

	if key_pair_generate(Some(rng),&mut u,v)!=0 {return None}
	if ecpsvdp_dh(&u,&w,&mut z)!=0 {return None}     

	for i in 0..2*EFS+1 {vz[i]=v[i]}
	for i in 0..EFS {vz[2*EFS+1+i]=z[i]}

	kdf2(sha,&vz,Some(p1),2*ecp::AESKEY,&mut k);

	for i in 0..ecp::AESKEY {k1[i]=k[i]; k2[i]=k[ecp::AESKEY+i]} 

	let mut c=cbc_iv0_encrypt(&k1,m);

	let mut l2:[u8;8]=[0;8];
	let p2l=p2.len();

	inttobytes(p2l,&mut l2);	

	for i in 0..p2l {
		c.push(p2[i]);
	}
	for i in 0..8 {
		c.push(l2[i]);
	}

	hmac(sha,&c,&k2,t.len(),t);

	for _ in 0..p2l+8 {c.pop();}
	
	return Some(c);
}

/* IEEE1363 ECIES decryption. Decryption of ciphertext V,C,T using private key U outputs plaintext M */
#[allow(non_snake_case)]
pub fn ecies_decrypt(sha: usize,p1: &[u8],p2: &[u8],v: &[u8],c: &mut Vec<u8>,t: &[u8],u: &[u8]) -> Option<Vec<u8>>  { 
	let mut z:[u8;EFS]=[0;EFS];
	let mut k1:[u8;ecp::AESKEY]=[0;ecp::AESKEY];
	let mut k2:[u8;ecp::AESKEY]=[0;ecp::AESKEY];
	let mut vz:[u8;3*EFS+1]=[0;3*EFS+1];	
	let mut k:[u8;2*ecp::AESKEY]=[0;2*ecp::AESKEY];

	let mut tag:[u8;32]=[0;32];  /* 32 is max length of tag */

	for i in 0..t.len() {tag[i]=t[i]}

	if ecpsvdp_dh(&u,&v,&mut z)!=0 {return None}

	for i in 0..2*EFS+1 {vz[i]=v[i]}
	for i in 0..EFS {vz[2*EFS+1+i]=z[i]}

	kdf2(sha,&vz,Some(p1),2*ecp::AESKEY,&mut k);

	for i in 0..ecp::AESKEY {k1[i]=k[i]; k2[i]=k[ecp::AESKEY+i]} 

	let m=cbc_iv0_decrypt(&k1,&c);

	if m==None {return None}

	let mut l2:[u8;8]=[0;8];
	let p2l=p2.len();

	inttobytes(p2l,&mut l2);	

	for i in 0..p2l {
		c.push(p2[i]);
	}
	for i in 0..8 {
		c.push(l2[i]);
	}

	hmac(sha,&c,&k2,t.len(),&mut tag);

	for _ in 0..p2l+8 {c.pop();}

	let mut same=true;
	for i in 0..t.len() {
		if t[i]!=tag[i] {same=false}
	}
	if !same {return None}
	
	return m;
}

