/*
Licensed to the Apache Software Foundation (ASF) under one
or more contributor license agreements.  See the NOTICE file
distributed with this work for additional information
regarding copyright ownership.  The ASF licenses this file
to you under the Apache License, Version 2.0 (the
"License"); you may not use this file except in compliance
with the License.  You may obtain a copy of the License at
if debug {println!("sf2= {}",self.tostring())}	
  http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing,
software distributed under the License is distributed on an
"AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
KIND, either express or implied.  See the License for the
specific language governing permissions and limitations
under the License.
*/

use rsa3072::big;
//use WWW::big::{BIG::muladd};
use rsa3072::dbig::DBIG;
use rsa3072::big::BIG;
use arch::Chunk;
use rand::RAND;

//#[cfg(D32)]
use arch::DChunk;

/* Finite field support - for RSA, DH etc. */
/* RSA/DH modulus length as multiple of BIGBITS */

pub const FFLEN:usize=8;

pub const FF_BITS:usize=(big::BIGBITS*FFLEN); /* Finite Field Size in bits - must be 256.2^n */
pub const HFLEN:usize=(FFLEN/2);  /* Useful for half-size RSA private key operations */

pub const P_MBITS:usize=(big::MODBYTES as usize)*8;
pub const P_OMASK:Chunk=((-1)<<(P_MBITS%big::BASEBITS));
pub const P_FEXCESS: Chunk=(1<<(big::BASEBITS*big::NLEN-P_MBITS-1));
pub const P_TBITS: usize=(P_MBITS%big::BASEBITS);


//#[derive(Copy, Clone)]
pub struct FF {
	v:Vec<BIG>,
	length:usize
}

//static mut debug:bool=false;

impl FF { 


    pub fn excess(a:&BIG) -> Chunk {
        return ((a.w[big::NLEN-1]&P_OMASK)>>(P_TBITS))+1;
    }


//#[cfg(D32)]
    pub fn pexceed(a: &BIG,b: &BIG) -> bool {
        let ea=FF::excess(a);
        let eb=FF::excess(b);
        if ((ea+1) as DChunk)*((eb+1) as DChunk) > P_FEXCESS as DChunk {return true}
        return false;
    }

//#[cfg(D32)]
    pub fn sexceed(a: &BIG) -> bool {
        let ea=FF::excess(a);
        if ((ea+1) as DChunk)*((ea+1) as DChunk) > P_FEXCESS as DChunk {return true}
        return false;
    }
/*
#[cfg(D64)]
    pub fn pexceed(a: &BIG,b: &BIG) -> bool {
        let ea=FF::excess(a);
        let eb=FF::excess(b);
        if (ea+1) > P_FEXCESS/(eb+1) {return true}
        return false;
    }

#[cfg(D64)]
    pub fn sexceed(a: &BIG) -> bool {
        let ea=FF::excess(a);
        if (ea+1) > P_FEXCESS/(ea+1) {return true}
        return false;
    }    
*/

/* Constructors */
	pub fn new_int(n:usize) -> FF {
		let mut f=FF{v:Vec::new(),length:0};
		for _ in 0..n {
			f.v.push(BIG::new());
		}
		f.length=n;
		return f;
	}
/*
	pub fn new_ints(x: &[&[i32];big::NLEN],n: usize) -> FF {
		let mut f=FF{v:Vec::new(),length:0};
		for i in 0..n {
			f.v.push(BIG::new_ints(x[i]));
		}
		f.length=n;
		return f;
	}
*/
	pub fn zero(&mut self) {
		for i in 0..self.length {
			self.v[i].zero();
		}
	}

	pub fn getlen(&self) -> usize {
		return self.length;
	}

/* set to integer */
	pub fn set(&mut self,m:isize) {
		self.zero();
		self.v[0].set(0,m as Chunk);
	}

/* copy from FF b */
	pub fn copy(&mut self,b: &FF) {
		for i in 0..self.length {
			self.v[i].copy(&b.v[i]);
	 	}
 	}

/* x=y<<n */
	pub fn dsucopy(&mut self,b: &FF) {
		for i in 0..b.length {
			self.v[b.length+i].copy(&b.v[i]);
			self.v[i].zero();
		}
	}

/* x=y */
	pub fn dscopy(&mut self,b: &FF) {
		for i in 0..b.length {
			self.v[i].copy(&b.v[i]);
			self.v[b.length+i].zero();
		}
	}

/* x=y>>n */
	pub fn sducopy(&mut self,b: &FF) {
		for i in 0..self.length {
			self.v[i].copy(&b.v[self.length+i]);
		}
	}

	pub fn one(&mut self) {
		self.v[0].one();
		for i in 1..self.length {
			self.v[i].zero();
		}
	}

/* test equals 0 */
	pub fn iszilch(&mut self) -> bool {
		for i in 0..self.length {
			if !self.v[i].iszilch() {return false}
		}
		return true;
	}

/* shift right by BIGBITS-bit words */
	pub fn shrw(&mut self,n: usize) {
    	let mut t= BIG::new(); 
		for i in 0..n {
			t.copy(&self.v[i+n]);
			self.v[i].copy(&t);
			self.v[i+n].zero();
		}
	}

/* shift left by BIGBITS-bit words */
	pub fn shlw(&mut self,n: usize) {
    	let mut t= BIG::new(); 		
		for i in 0..n {
			t.copy(&self.v[i]);
			self.v[n+i].copy(&t);
			self.v[i].zero();
		}
	}

/* extract last bit */
	pub fn parity(&self) -> isize {
		return self.v[0].parity();
	}

	pub fn lastbits(&mut self,m: usize) -> isize {
		return self.v[0].lastbits(m);
	}

/* compare x and y - must be normalised, and of same length */
	pub fn comp(a: &FF,b: &FF) -> isize {
		let mut i=a.length-1;

		loop {
			let j=BIG::comp(&a.v[i],&b.v[i]);
			if j!=0 {return j}
			if i==0 {break;}
			i-=1;
		}
		return 0;
	}	

/* recursive add */
	pub fn radd(&mut self,vp: usize,x: &FF,xp: usize,y: &FF,yp: usize,n: usize) {
		for i in 0..n {
			self.v[vp+i].copy(&x.v[xp+i]);
			self.v[vp+i].add(&y.v[yp+i]);
		}
	}	

/* recursive inc */
	pub fn rinc(&mut self,vp: usize,y: &FF,yp: usize,n: usize) {
		for i in 0..n {
			self.v[vp+i].add(&y.v[yp+i]);
		}
	}

	pub fn rsinc(&mut self,n: usize) {
		let mut t=BIG::new();
		for i in 0..n {
			t.copy(&self.v[i]);
			self.v[n+i].add(&t);
		}		
	}

/* recursive sub */
	pub fn rsub(&mut self,vp: usize,x: &FF,xp: usize,y: &FF,yp: usize,n: usize) {
		for i in 0..n {
			self.v[vp+i].copy(&x.v[xp+i]);
			self.v[vp+i].sub(&y.v[yp+i]);
		}
	}

/* recursive dec */
	pub fn rdec(&mut self,vp: usize,y: &FF,yp: usize,n: usize) {
		for i in 0..n {
			self.v[vp+i].sub(&y.v[yp+i]);
		}
	}

/* simple add */
	pub fn add(&mut self,b: &FF) {
		for i in 0..self.length {
			self.v[i].add(&b.v[i]);
		}
	}

/* simple sub */
	pub fn sub(&mut self,b: &FF) {
		for i in 0..self.length {
			self.v[i].sub(&b.v[i]);
		}
	}
	
/* reverse sub */
	pub fn revsub(&mut self,b: &FF) {
		for i in 0..self.length {
			self.v[i].rsub(&b.v[i]);
		}
	}

/* normalise - but hold any overflow in top part unless n<0 */
	pub fn rnorm(&mut self,vp: usize,n: isize) {
		let mut trunc=false;
		let mut carry:Chunk;
		let mut nn:usize=n as usize; 
		if n<0 { /* -v n signals to do truncation */
			nn=(-n) as usize;
			trunc=true;
		}
		for i in 0..nn-1 {
			carry=self.v[vp+i].norm();
			self.v[vp+i].xortop(carry<<P_TBITS);
			self.v[vp+i+1].w[0]+=carry; //incl(carry);
		}
		carry=self.v[vp+nn-1].norm();
		if trunc {
			self.v[vp+nn-1].xortop(carry<<P_TBITS);
		}
	}

	pub fn norm(&mut self) {
		let n:isize=self.length as isize;
		self.rnorm(0,n);
	}

/* increment/decrement by a small integer */
	pub fn inc(&mut self,m: isize) {
		self.v[0].inc(m);
		self.norm();
	}

	pub fn dec(&mut self,m: isize) {
		self.v[0].dec(m);
		self.norm();
	}

/* shift left by one bit */
	pub fn shl(&mut self) {
		let mut delay_carry:isize=0;
		for i in 0..self.length-1 {
			let carry=self.v[i].fshl(1);
			self.v[i].inc(delay_carry);
			self.v[i].xortop((carry as Chunk)<<P_TBITS);
			delay_carry=carry;
		}
		self.v[self.length-1].fshl(1);
		self.v[self.length-1].inc(delay_carry);
	}

/* shift right by one bit */

	pub fn shr(&mut self) {
		let mut i=self.length-1;
		while i>0 {
			let carry=self.v[i].fshr(1);
			self.v[i-1].xortop((carry as Chunk)<<P_TBITS);
			i-=1;
		}
		self.v[0].fshr(1);
	}

/* Convert to Hex String */
	pub fn tostring(&mut self) -> String {
		self.norm();
		let mut s = String::new();
		let mut i:usize=self.length-1;
		loop {
			s=s+self.v[i].tostring().as_ref();
			if i==0 {break}
			i-=1;
		}
		return s;
	}

/* Convert to Hex String 
	pub fn tostr(&mut self,n:usize) -> String {
		let mut t=FF::new_int(n);
		for i in 0..n {
			t.v[i].copy(&self.v[i]);
		}
		t.norm();
		let mut s = String::new();
		let mut i:usize=t.length-1;
		loop {
			s=s+t.v[i].tostring().as_ref();
			if i==0 {break}
			i-=1;
		}
		return s;
	}*/

/* Convert FFs to/from byte arrays */
	pub fn tobytes(&mut self,b: &mut [u8]) {
		for i in 0..self.length {
			self.v[i].tobytearray(b,(self.length-i-1)*(big::MODBYTES as usize))
		}
	}

	pub fn frombytes(x: &mut FF,b: &[u8]) {
		for i in 0..x.length {
			x.v[i]=BIG::frombytearray(b,(x.length-i-1)*(big::MODBYTES as usize))
		}
	}

/* in-place swapping using xor - side channel resistant - lengths must be the same */
	pub fn cswap(a: &mut FF,b: &mut FF,d: isize) {
		for i in 0..a.length {
			a.v[i].cswap(&mut b.v[i],d);
		}
	}

/* z=x*y, t is workspace */
	fn karmul(&mut self,vp: usize,x: &FF,xp: usize,y: &FF,yp: usize,t: *mut FF,tp: usize,n: usize) {
		if n==1 {
			let xx= BIG::new_copy(&x.v[xp]);
			let yy= BIG::new_copy(&y.v[yp]);
			let mut d=BIG::mul(&xx,&yy);
			self.v[vp+1]=d.split(8*big::MODBYTES);
			self.v[vp].dcopy(&d);
			return;
		}
		let nd2=n/2;
		self.radd(vp,x,xp,x,xp+nd2,nd2);
		self.rnorm(vp,nd2 as isize);       /* Important - required for 32-bit build */
		self.radd(vp+nd2,y,yp,y,yp+nd2,nd2);
		self.rnorm(vp+nd2,nd2 as isize);    /* Important - required for 32-bit build */
		unsafe{
			(*t).karmul(tp,self,vp,self,vp+nd2,t,tp+n,nd2);
		}
		self.karmul(vp,x,xp,y,yp,t,tp+n,nd2);
		self.karmul(vp+n,x,xp+nd2,y,yp+nd2,t,tp+n,nd2);
		unsafe {
			(*t).rdec(tp,self,vp,n);
			(*t).rdec(tp,self,vp+n,n);
			self.rinc(vp+nd2,&(*t),tp,n);
		}
		self.rnorm(vp,(2*n) as isize);
	}

	fn karsqr(&mut self,vp: usize,x: &FF,xp: usize,t: *mut FF,tp: usize,n: usize) {
		if n==1 {
			let xx= BIG::new_copy(&x.v[xp]);	
			let mut d=BIG::sqr(&xx);
			self.v[vp+1].copy(&d.split(8*big::MODBYTES));
			self.v[vp].dcopy(&d);
			return;
		}	

		let nd2=n/2;
		self.karsqr(vp,x,xp,t,tp+n,nd2);
		self.karsqr(vp+n,x,xp+nd2,t,tp+n,nd2);
		unsafe {
			(*t).karmul(tp,x,xp,x,xp+nd2,t,tp+n,nd2);
			self.rinc(vp+nd2,&(*t),tp,n);
			self.rinc(vp+nd2,&(*t),tp,n);
		}
		self.rnorm(vp+nd2,n as isize);
	}

/* Calculates Least Significant bottom half of x*y */
	fn karmul_lower(&mut self,vp: usize,x: &FF,xp: usize,y: &FF,yp: usize,t: *mut FF,tp: usize,n: usize) { 
		if n==1 { /* only calculate bottom half of product */
			self.v[vp].copy(&BIG::smul(&x.v[xp],&y.v[yp]));
			return;
		}
		let nd2=n/2;

		self.karmul(vp,x,xp,y,yp,t,tp+n,nd2);
		unsafe {
			(*t).karmul_lower(tp,x,xp+nd2,y,yp,t,tp+n,nd2);
			self.rinc(vp+nd2,&(*t),tp,nd2);
			(*t).karmul_lower(tp,x,xp,y,yp+nd2,t,tp+n,nd2);
			self.rinc(vp+nd2,&(*t),tp,nd2);
		}
		let sn:isize=nd2 as isize;
		self.rnorm(vp+nd2,-sn);  /* truncate it */
	}

/* Calculates Most Significant upper half of x*y, given lower part */
	fn karmul_upper(&mut self,x: &FF,y: &FF,t: *mut FF,n: usize) { 
		let nd2=n/2;
		self.radd(n,x,0,x,nd2,nd2);
		self.radd(n+nd2,y,0,y,nd2,nd2);
		self.rnorm(n,nd2 as isize);
		self.rnorm(n+nd2,nd2 as isize);

		unsafe {			
			(*t).karmul(0,self,n+nd2,self,n,t,n,nd2);  /* t = (a0+a1)(b0+b1) */

		}
		self.karmul(n,x,nd2,y,nd2,t,n,nd2); /* z[n]= a1*b1 */
					/* z[0-nd2]=l(a0b0) z[nd2-n]= h(a0b0)+l(t)-l(a0b0)-l(a1b1) */
		unsafe {
			(*t).rdec(0,self,n,n);              /* t=t-a1b1  */										
			self.rsinc(nd2);  /* z[nd2-n]+=l(a0b0) = h(a0b0)+l(t)-l(a1b1)  */
			self.rdec(nd2,&(*t),0,nd2);   /* z[nd2-n]=h(a0b0)+l(t)-l(a1b1)-l(t-a1b1)=h(a0b0) */			
		}

		let sn:isize=n as isize;
		self.rnorm(0,-sn);		/* a0b0 now in z - truncate it */
		unsafe {
			(*t).rdec(0,self,0,n);         /* (a0+a1)(b0+b1) - a0b0 */
			self.rinc(nd2,&(*t),0,n);
		}
		self.rnorm(nd2,sn);
	}

/* z=x*y. Assumes x and y are of same length. */
	pub fn mul(x: &FF,y: &FF) -> FF {
		let n=x.length;
		let mut z=FF::new_int(2*n);
		let mut t=FF::new_int(2*n);
	//	x.norm(); y.norm();
		z.karmul(0,&x,0,&y,0,&mut t,0,n);
		return z;
	}

/* return low part of product this*y */
	pub fn lmul(&mut self,y: &FF) {
		let n=self.length;
		let mut t=FF::new_int(2*n);
		let mut x=FF::new_int(n); x.copy(&self);
	//	x.norm(); y.norm();		
		self.karmul_lower(0,&x,0,&y,0,&mut t,0,n);
	}

/* Set b=b mod c */
	pub fn rmod(&mut self,m: &FF) {
		let mut k=1;  
		let n=m.length;
		let mut c=FF::new_int(n); c.copy(m);

		self.norm();
		if FF::comp(&self,&c)<0 {return}

		c.shl();
		while FF::comp(&self,&c)>=0 {
			c.shl();
			k+=1;
		}

		while k>0 {
			c.shr();
			if FF::comp(&self,&c)>=0 {
				self.sub(&c);
				self.norm();
			}
			k-=1;
		}
	}

/* z=x^2 */
	pub fn sqr(x: &FF) -> FF {
		let n=x.length;
		let mut z=FF::new_int(2*n);
		let mut t=FF::new_int(2*n);
	//	x.norm();
		z.karsqr(0,&x,0,&mut t,0,n);
		return z;
	}

/* return This mod modulus, ms is modulus, md is Montgomery Constant */
	pub fn reduce(&mut self,ms: &FF,md: &FF) -> FF { /* fast karatsuba Montgomery reduction */
		let n=ms.length;
		let mut t=FF::new_int(2*n);
		let mut r=FF::new_int(n);
		let mut m=FF::new_int(n);

		r.sducopy(&self);
		m.karmul_lower(0,&self,0,&md,0,&mut t,0,n);
		self.karmul_upper(&ms,&m,&mut t,n);
	
		m.sducopy(self);
		r.add(&ms);	
		r.sub(&m);	
		r.norm();

		return r;
	}

/* Set r=this mod b */
/* this is of length - 2*n */
/* r,b is of length - n */
	pub fn dmod(&mut self,b: &FF) -> FF {
		let n=b.length;
		let mut m=FF::new_int(2*n);
		let mut x=FF::new_int(2*n);
		let mut r=FF::new_int(n);

		x.copy(&self);
		x.norm();
		m.dsucopy(&b); let mut k=big::BIGBITS*n;

		while FF::comp(&x,&m)>=0 {
			x.sub(&m);
			x.norm();
		}

		while k>0 {	
			m.shr();

			if FF::comp(&x,&m)>=0 {
				x.sub(&m);
				x.norm();
			}
			k-=1;
		}

		r.copy(&x);
		r.rmod(b);
		return r;
	}

/* Set return=1/this mod p. Binary method - a<p on entry */

	pub fn invmodp(&mut self,p: &FF) {
		let n=p.length;

		let mut u=FF::new_int(n);
		let mut v=FF::new_int(n);
		let mut x1=FF::new_int(n);
		let mut x2=FF::new_int(n);
		let mut t=FF::new_int(n);
		let mut one=FF::new_int(n);

		one.one();
		u.copy(&self);
		v.copy(&p);
		x1.copy(&one);
		x2.zero();

	// reduce n in here as well! 
		while FF::comp(&u,&one)!=0 && FF::comp(&v,&one)!=0 {
			while u.parity()==0 {
				u.shr();
				if x1.parity()!=0 {
					x1.add(&p);
					x1.norm();
				}
				x1.shr();
			}
			while v.parity()==0 {
				v.shr(); 
				if x2.parity()!=0 {
					x2.add(&p);
					x2.norm();
				}
				x2.shr();
			}
			if FF::comp(&u,&v)>=0 {
				u.sub(&v);
				u.norm();
				if FF::comp(&x1,&x2)>=0 {
					x1.sub(&x2);
				} else {
					t.copy(&p);
					t.sub(&x2);
					x1.add(&t);
				}
				x1.norm();
			} else {
				v.sub(&u);
				v.norm();
				if FF::comp(&x2,&x1)>=0 { 
					x2.sub(&x1);
				} else {
					t.copy(&p);
					t.sub(&x1);
					x2.add(&t);
				}
				x2.norm();
			}
		}
		if FF::comp(&u,&one)==0 {
			self.copy(&x1);
		} else {
			self.copy(&x2);
		}
	}

/* nresidue mod m */
	pub fn nres(&mut self,m: &FF) {
		let n=m.length;
		if n==1 {
			let mut d=DBIG::new_scopy(&(self.v[0]));
			d.shl(big::NLEN*(big::BASEBITS as usize));
			self.v[0].copy(&d.dmod(&(m.v[0])));
		} else {
			let mut d=FF::new_int(2*n);
			d.dsucopy(&self);
			self.copy(&d.dmod(m));
		}
	}

	pub fn redc(&mut self,m: &FF,md: &FF) {
		let n=m.length;
		if n==1 {
			let mut d=DBIG::new_scopy(&(self.v[0]));
			self.v[0].copy(&BIG::monty(&(m.v[0]),((1 as Chunk)<<big::BASEBITS)-md.v[0].w[0],&mut d));			
		} else {
			let mut d=FF::new_int(2*n);
			self.rmod(m);
			d.dscopy(&self);
			self.copy(&d.reduce(&m,&md));
			self.rmod(m);
		}
	}

	pub fn mod2m(&mut self,m: usize) {
	 	for i in m..self.length {
			self.v[i].zero()
		}
	}

/* U=1/a mod 2^m - Arazi & Qi */
	pub fn invmod2m(&self) -> FF {
		let n=self.length;

		let mut b=FF::new_int(n);
		let mut c=FF::new_int(n);
		let mut u=FF::new_int(n);

		u.zero();
		u.v[0].copy(&self.v[0]);
		u.v[0].invmod2m();

		let mut i=1;
		while i<n {
			b.copy(&self); b.mod2m(i);
			let mut t=FF::mul(&u,&b); t.shrw(i); b.copy(&t);
			c.copy(&self); c.shrw(i); c.mod2m(i);
			c.lmul(&u); c.mod2m(i);

			b.add(&c); b.norm();
			b.lmul(&u); b.mod2m(i);

			c.one(); c.shlw(i); b.revsub(&c); b.norm();
			b.shlw(i);
			u.add(&b);
			i<<=1;
		}
		u.norm();
		return u;
	}	

	pub fn random(&mut self,rng: &mut RAND) {
		let n=self.length;
		for i in 0..n {
			self.v[i].copy(&BIG::random(rng))
		}
	/* make sure top bit is 1 */
		while self.v[n-1].nbits()<(big::MODBYTES as usize)*8 {
			self.v[n-1].copy(&BIG::random(rng));
		}
	}

/* generate random x less than p */
	pub fn randomnum(&mut self,p: &FF,rng: &mut RAND) {
		let n=self.length;
		let mut d=FF::new_int(2*n);

		for i in 0..2*n {
			d.v[i].copy(&BIG::random(rng));
		}
		self.copy(&d.dmod(p));
	}

/* this*=y mod p */
	pub fn modmul(&mut self,y: &FF,p: &FF,nd: &FF) {
		if FF::pexceed(&self.v[self.length-1],&y.v[y.length-1]) {
			self.rmod(p)
		}
		let n=p.length;
		if n==1 {
			let mut d=BIG::mul(&self.v[0],&y.v[0]);
			self.v[0].copy(&BIG::monty(&(p.v[0]),((1 as Chunk)<<big::BASEBITS)-nd.v[0].w[0],&mut d));				
		} else {
			let mut d=FF::mul(&self,y);
			self.copy(&d.reduce(p,nd));
		}
	}

/* this*=y mod p */
	pub fn modsqr(&mut self,p: &FF,nd: &FF) {
		if FF::sexceed(&self.v[self.length-1]) {
			self.rmod(p);
		}
		let n=p.length;
		if n==1 {
			let mut d=BIG::sqr(&self.v[0]);
			self.v[0].copy(&BIG::monty(&(p.v[0]),((1 as Chunk)<<big::BASEBITS)-nd.v[0].w[0],&mut d));			
		} else {		
			let mut d=FF::sqr(&self);
			d.norm();
			self.copy(&d.reduce(p,nd));
		}
	}

/* this=this^e mod p using side-channel resistant Montgomery Ladder, for large e */
	pub fn skpow(&mut self,e: &FF,p: &FF) {
		let n=p.length;
		let mut r0=FF::new_int(n);
		let mut r1=FF::new_int(n);
		let nd=p.invmod2m();

		self.rmod(p);
		r0.one();
		r1.copy(&self);
		r0.nres(p);
		r1.nres(p);

		let mut i=8*(big::MODBYTES as usize)*n-1;
		loop {
			let b=(e.v[i/(big::BIGBITS as usize)]).bit(i%(big::BIGBITS as usize)) as isize;
			self.copy(&r0);
			self.modmul(&r1,p,&nd);

			FF::cswap(&mut r0,&mut r1,b);
			r0.modsqr(p,&nd);

			r1.copy(&self);
			FF::cswap(&mut r0,&mut r1,b);
			if i==0 {break}
			i-=1;
		}
		self.copy(&r0);
		self.redc(p,&nd);
	}

/* this =this^e mod p using side-channel resistant Montgomery Ladder, for short e */
	pub fn skpows(&mut self,e: &BIG,p: &FF) {
		let n=p.length;
		let mut r0=FF::new_int(n);
		let mut r1=FF::new_int(n);
		let nd=p.invmod2m();

		self.rmod(p);
		r0.one();
		r1.copy(&self);
		r0.nres(p);
		r1.nres(p);

		let mut i=8*(big::MODBYTES as usize)-1;
		loop {
			let b=e.bit(i);
			self.copy(&r0);
			self.modmul(&r1,p,&nd);

			FF::cswap(&mut r0,&mut r1,b);
			r0.modsqr(p,&nd);

			r1.copy(&self);
			FF::cswap(&mut r0,&mut r1,b);
			if i==0 {break}
			i-=1;			
		}
		self.copy(&r0);
		self.redc(p,&nd);
	}




/* raise to an integer power - right-to-left method */
	pub fn power(&mut self,e: isize,p: &FF) {
		let n=p.length;
		let mut w=FF::new_int(n);
		let nd=p.invmod2m();
		let mut f=true;
		let mut ee=e;

		w.copy(&self);
		w.nres(p);

		if ee==2 {
			self.copy(&w);
			self.modsqr(p,&nd);
		} else {
			loop {
				if ee%2==1 {
					if f {
						self.copy(&w);
					} else {self.modmul(&w,p,&nd)}
					f=false;
				}
				ee>>=1;
				if ee==0 {break}
				w.modsqr(p,&nd);	
			}
		}

		self.redc(p,&nd);
	}

/* this=this^e mod p, faster but not side channel resistant */
	pub fn pow(&mut self,e: &FF,p: &FF) {
		let n=p.length;
		let mut w=FF::new_int(n);
		let nd=p.invmod2m();

		w.copy(&self);
		self.one();
		self.nres(p);
		w.nres(p);
		let mut i=8*(big::MODBYTES as usize)*n-1;
		loop {
			self.modsqr(p,&nd);
			let b=(e.v[i/(big::BIGBITS as usize)]).bit(i%(big::BIGBITS as usize)) as isize;			
			if b==1 {self.modmul(&w,p,&nd)}
			if i==0 {break}
			i-=1;				
		}
		self.redc(p,&nd);
	}

/* double exponentiation r=x^e.y^f mod p */
	pub fn pow2(&mut self,e: &BIG,y: &FF,f: &BIG,p: &FF) {
		let n=p.length;
		let mut xn=FF::new_int(n);
		let mut yn=FF::new_int(n);
		let mut xy=FF::new_int(n);
		let nd=p.invmod2m();

		xn.copy(&self);
		yn.copy(y);
		xn.nres(p);
		yn.nres(p);
		xy.copy(&xn); xy.modmul(&yn,p,&nd);
		self.one();
		self.nres(p);

		let mut i=8*(big::MODBYTES as usize)-1;
		loop {
			let eb=e.bit(i);
			let fb=f.bit(i);
			self.modsqr(p,&nd);
			if eb==1 {
				if fb==1 {
					self.modmul(&xy,p,&nd);
				} else {self.modmul(&xn,p,&nd)}
			} else	{
				if fb==1 {self.modmul(&yn,p,&nd)}
			}
			if i==0 {break}
			i-=1;				
		}
		self.redc(p,&nd);
	}

	pub fn igcd(x: isize,y: isize) -> isize { /* integer GCD, returns GCD of x and y */

		if y==0 {return x}	
		let mut xx=x;
		let mut yy=y;		
		loop {
			let r=xx%yy;
			if r==0 {break}
			xx=yy;yy=r;
		}
		return yy;
	}

/* quick and dirty check for common factor with n */
	pub fn cfactor(&self,s: isize) -> bool {
		let n=self.length;

		let mut x=FF::new_int(n);
		let mut y=FF::new_int(n);

		y.set(s);
		x.copy(&self);
		x.norm();

		x.sub(&y);
		x.norm();

		while !x.iszilch() && x.parity()==0 {x.shr()}

		while FF::comp(&x,&y)>0 {
			x.sub(&y);
			x.norm();
			while !x.iszilch() && x.parity()==0 {x.shr()}
		}

		let g=x.v[0].get(0) as isize;
		let r=FF::igcd(s,g);
		if r>1 {return true}
		return false
	}

/* Miller-Rabin test for primality. Slow. */
	pub fn prime(pp: &FF,rng: &mut RAND) -> bool {
		let mut s=0;
		let n=pp.length;
		let mut d=FF::new_int(n);
		let mut x=FF::new_int(n);
		let mut unity=FF::new_int(n);
		let mut nm1=FF::new_int(n);
		let mut p=FF::new_int(n); p.copy(pp);

		let sf=4849845; /* 3*5*.. *19 */
		p.norm();

		if p.cfactor(sf) {return false}
		unity.one();
		nm1.copy(&p);
		nm1.sub(&unity);
		nm1.norm();
		d.copy(&nm1);

		while d.parity()==0 {
			d.shr();
			s+=1;
		}
		if s==0 {return false}
		for _ in 0..10 {
			x.randomnum(&p,rng);

			x.pow(&d,&p);
		
			if FF::comp(&x,&unity)==0 || FF::comp(&x,&nm1)==0 {continue}
			let mut looper=false;
			for _ in 1..s {
				x.power(2,&p);
				if FF::comp(&x,&unity)==0 {return false}
				if FF::comp(&x,&nm1)==0 {looper=true; break}
			}
			if looper {continue}
			return false;
		}

		return true;
	}

}
/*
fn main()
{
	let mut x=FF::new_int(4);
	let mut y=FF::new_int(4);

	x.one(); y.one();
	let mut z=FF::mul(&mut x,&mut y);

	println!("z= {}",z.tostring());
}
*/
