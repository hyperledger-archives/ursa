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

use secp256k1::fp::FP;
use secp256k1::big::BIG;
use secp256k1::big;
use secp256k1::rom;

pub struct ECP {
	x:FP,
	y:FP,
	z:FP,
//	inf: bool
}

pub const WEIERSTRASS:usize=0;
pub const EDWARDS:usize=1;
pub const MONTGOMERY:usize=2;
pub const NOT: usize=0;
pub const BN: usize=1;
pub const BLS: usize=2;
pub const D_TYPE: usize=0;
pub const M_TYPE: usize=1;
pub const POSITIVEX: usize=0;
pub const NEGATIVEX: usize=1;

pub const CURVETYPE:usize=WEIERSTRASS;
pub const CURVE_PAIRING_TYPE:usize=NOT;
pub const SEXTIC_TWIST:usize=NOT;
pub const SIGN_OF_X:usize=NOT;

pub const HASH_TYPE:usize=32;
pub const AESKEY:usize=16;

#[allow(non_snake_case)]
impl ECP {

	pub fn pnew() -> ECP {
		ECP {
				x: FP::new(),
				y: FP::new_int(1),
				z: FP::new(),
//				inf: true
		}

	}

	pub fn new() -> ECP {
		let mut E=ECP::pnew();
		if CURVETYPE==EDWARDS {
			E.z.one();
		}
		return E;
	}

/* set (x,y) from two BIGs */
	pub fn new_bigs(ix: &BIG,iy: &BIG) -> ECP {
		let mut E=ECP::new();
		E.x.bcopy(ix); 
		E.y.bcopy(iy); 
		E.z.one(); 
		let mut rhs=ECP::rhs(&mut E.x);
		if CURVETYPE==MONTGOMERY {
			if rhs.jacobi()==1 {
			//	E.inf=false;
			} else {E.inf()}
		} else {
			let mut y2=FP::new_copy(&E.y);
			y2.sqr();	
			if y2.equals(&mut rhs) {
			//	E.inf=false
			} else {E.inf()}
		}
		return E;
	}

/* set (x,y) from BIG and a bit */
	pub fn new_bigint(ix: &BIG,s: isize) -> ECP {
		let mut E=ECP::new();
		E.x.bcopy(ix); 
		E.z.one(); 

		let mut rhs=ECP::rhs(&mut E.x);

		if rhs.jacobi()==1 {
			let mut ny=rhs.sqrt();
			if ny.redc().parity()!=s {ny.neg()}
			E.y.copy(&ny);
		//	E.inf=false;
		} else {E.inf()}
		return E;
	}

#[allow(non_snake_case)]
/* set from x - calculate y from curve equation */
	pub fn new_big(ix: &BIG) -> ECP {
		let mut E=ECP::new();
		E.x.bcopy(ix); 
		E.z.one(); 
		let mut rhs=ECP::rhs(&mut E.x);
		if rhs.jacobi()==1 {
			if CURVETYPE!=MONTGOMERY {E.y.copy(&rhs.sqrt())}
		//	E.inf=false;
		} else {E.inf();}
		return E;
	}

/* set this=O */
	pub fn inf(&mut self) {
	//	self.inf=true;
		self.x.zero();
		if CURVETYPE!=MONTGOMERY {
			self.y.one();
		}
		if CURVETYPE!=EDWARDS {
			self.z.zero();
		} else {self.z.one()}
	}

/* Calculate RHS of curve equation */
	fn rhs(x: &mut FP) -> FP {
		x.norm();
		let mut r=FP::new_copy(x);
		r.sqr();

		if CURVETYPE==WEIERSTRASS { // x^3+Ax+B
			let b=FP::new_big(&BIG::new_ints(&rom::CURVE_B));
			r.mul(x);
			if rom::CURVE_A==-3 {
				let mut cx=FP::new_copy(x);
				cx.imul(3);
				cx.neg(); cx.norm();
				r.add(&cx);
			}
			r.add(&b);
		}
		if CURVETYPE==EDWARDS { // (Ax^2-1)/(Bx^2-1) 
			let mut b=FP::new_big(&BIG::new_ints(&rom::CURVE_B));
			let one=FP::new_int(1);
			b.mul(&r);
			b.sub(&one);
			b.norm();
			if rom::CURVE_A==-1 {r.neg()}
			r.sub(&one); r.norm();
			b.inverse();
			r.mul(&b);
		}
		if CURVETYPE==MONTGOMERY { // x^3+Ax^2+x
			let mut x3=FP::new();
			x3.copy(&r);
			x3.mul(x);
			r.imul(rom::CURVE_A);
			r.add(&x3);
			r.add(&x);
		}
		r.reduce();
		return r;
	}

/* test for O point-at-infinity */
	pub fn is_infinity(&self) -> bool {
	//	if self.inf {return true}
		let mut xx=FP::new_copy(&self.x);
		let mut zz=FP::new_copy(&self.z);

		if CURVETYPE==EDWARDS {
			let mut yy=FP::new_copy(&self.y);
			return xx.iszilch() && yy.equals(&mut zz);
		}
		if CURVETYPE==WEIERSTRASS {
			return xx.iszilch() && zz.iszilch();
		}
		if CURVETYPE==MONTGOMERY {
			return zz.iszilch();
		}
		return true;
 	}

/* Conditional swap of P and Q dependant on d */
	pub fn cswap(&mut self,Q: &mut ECP,d: isize) {
		self.x.cswap(&mut Q.x,d);
		if CURVETYPE!=MONTGOMERY {self.y.cswap(&mut Q.y,d)}
		self.z.cswap(&mut Q.z,d);
/*		
		let mut bd=true;
		if d==0 {bd=false}
		bd=bd&&(self.inf!=Q.inf);
		self.inf=bd!=self.inf;
		Q.inf=bd!=Q.inf; */
	}

/* Conditional move of Q to P dependant on d */
	pub fn cmove(&mut self,Q: &ECP,d: isize) {
		self.x.cmove(&Q.x,d);
		if CURVETYPE!=MONTGOMERY {self.y.cmove(&Q.y,d)}
		self.z.cmove(&Q.z,d);
	/*	
		let mut bd=true;
		if d==0 {bd=false}
		self.inf=(self.inf!=((self.inf!=Q.inf)&&bd)); */
	}

/* return 1 if b==c, no branching */
	fn teq(b: i32,c: i32) -> isize {
		let mut x=b^c;
		x-=1;  // if x=0, x now -1
		return ((x>>31)&1) as isize;
	}

/* this=P */
	pub fn copy(&mut self,P: & ECP) {
		self.x.copy(&P.x);
		if CURVETYPE!=MONTGOMERY {self.y.copy(&P.y)}
		self.z.copy(&P.z);
	//	self.inf=P.inf;
}

/* this=-this */
	pub fn neg(&mut self) {
	//	if self.is_infinity() {return}
		if CURVETYPE==WEIERSTRASS {
			self.y.neg(); self.y.norm();
		}
		if CURVETYPE==EDWARDS {
			self.x.neg(); self.x.norm();
		}
		return;
	}
/* multiply x coordinate */
	pub fn mulx(&mut self,c: &mut FP) {
		self.x.mul(c);
	}

/* Constant time select from pre-computed table */
	fn selector(&mut self, W: &[ECP],b: i32) {   // unsure about &[& syntax. An array of pointers I hope..
		let mut MP=ECP::new();
		let m=b>>31;
		let mut babs=(b^m)-m;

		babs=(babs-1)/2;

		self.cmove(&W[0],ECP::teq(babs,0));  // conditional move
		self.cmove(&W[1],ECP::teq(babs,1));
		self.cmove(&W[2],ECP::teq(babs,2));
		self.cmove(&W[3],ECP::teq(babs,3));
		self.cmove(&W[4],ECP::teq(babs,4));
		self.cmove(&W[5],ECP::teq(babs,5));
		self.cmove(&W[6],ECP::teq(babs,6));
		self.cmove(&W[7],ECP::teq(babs,7));
 
		MP.copy(self);
		MP.neg();
		self.cmove(&MP,(m&1) as isize);
	}

/* Test P == Q */
	pub fn equals(&mut self,Q: &mut ECP) -> bool {
	//	if self.is_infinity() && Q.is_infinity() {return true}
	//	if self.is_infinity() || Q.is_infinity() {return false}

		let mut a=FP::new();
		let mut b=FP::new();
		a.copy(&self.x); a.mul(&Q.z); 
		b.copy(&Q.x); b.mul(&self.z); 
		if !a.equals(&mut b) {return false}
		if CURVETYPE!=MONTGOMERY {
			a.copy(&self.y); a.mul(&Q.z); 
			b.copy(&Q.y); b.mul(&self.z); 
			if !a.equals(&mut b) {return false}
		}
		return true;
	}

/* set to affine - from (x,y,z) to (x,y) */
	pub fn affine(&mut self) {
		if self.is_infinity() { return}
		let mut one=FP::new_int(1);
		if self.z.equals(&mut one) {return}
		self.z.inverse();

		self.x.mul(&self.z); self.x.reduce();
		if CURVETYPE!=MONTGOMERY {
			self.y.mul(&self.z); self.y.reduce();
		}
		self.z.copy(&one);
	}

/* extract x as a BIG */
	pub fn getx(&mut self) -> BIG {
		self.affine();
		return self.x.redc();
	}

/* extract y as a BIG */
	pub fn gety(&mut self) -> BIG {
		self.affine();
		return self.y.redc();
	}

/* get sign of Y */
	pub fn gets(&mut self) -> isize {
		self.affine();
		let y=self.gety();
		return y.parity();
	}

/* extract x as an FP */
	pub fn getpx(&self) -> FP {
		let w=FP::new_copy(&self.x);
		return w;
	}
/* extract y as an FP */
	pub fn getpy(&self) -> FP {
		let w=FP::new_copy(&self.y);
		return w;
	}

/* extract z as an FP */
	pub fn getpz(&self) -> FP {
		let w=FP::new_copy(&self.z);
		return w;
	}

/* convert to byte array */
	pub fn tobytes(&mut self,b: &mut [u8],compress: bool) {
		let mb=big::MODBYTES as usize;
		let mut t:[u8;big::MODBYTES as usize]=[0;big::MODBYTES as usize];

		self.affine();
		self.x.redc().tobytes(&mut t);
		for i in 0..mb {b[i+1]=t[i]}

		if CURVETYPE==MONTGOMERY {
			b[0]=0x06;
			return;
		} 
	
		if compress {
			b[0]=0x02;
			if self.y.redc().parity()==1 {b[0]=0x03}
			return;
		}

		b[0]=0x04;
		
		self.y.redc().tobytes(&mut t);
		for i in 0..mb {b[i+mb+1]=t[i]}
	}

/* convert from byte array to point */
	pub fn frombytes(b: &[u8]) -> ECP {
		let mut t:[u8;big::MODBYTES as usize]=[0;big::MODBYTES as usize];
		let mb=big::MODBYTES as usize;
		let p=BIG::new_ints(&rom::MODULUS);

		for i in 0..mb {t[i]=b[i+1]}
		let px=BIG::frombytes(&t);
		if BIG::comp(&px,&p)>=0 {return ECP::new()}

		if CURVETYPE==MONTGOMERY {
			return ECP::new_big(&px)
		}

		if b[0]==0x04 {
			for i in 0..mb {t[i]=b[i+mb+1]}
			let py=BIG::frombytes(&t);
			if BIG::comp(&py,&p)>=0 {return ECP::new()}
			return ECP::new_bigs(&px,&py);
		} 

		if b[0]==0x02 || b[0]==0x03 {
			return ECP::new_bigint(&px,(b[0]&1) as isize)
		}

		return ECP::new()
	}

/* convert to hex string */
	pub fn tostring(&mut self) -> String {
	 	if self.is_infinity() {self.inf(); return String::from("infinity")}
		self.affine();
		if CURVETYPE==MONTGOMERY {
			return format!("({})",self.x.redc().tostring());
		} else {return format!("({},{})",self.x.redc().tostring(),self.y.redc().tostring())} ; 
	}

/* this*=2 */
	pub fn dbl(&mut self) {
	//	if self.inf {return}

		if CURVETYPE==WEIERSTRASS {

			if rom::CURVE_A==0 {
				let mut t0=FP::new_copy(&self.y);     
				t0.sqr();
				let mut t1=FP::new_copy(&self.y);
				t1.mul(&self.z);
				let mut t2=FP::new_copy(&self.z);
				t2.sqr();

				self.z.copy(&t0);
				self.z.add(&t0); self.z.norm(); 
				self.z.dbl(); self.z.dbl(); self.z.norm();
				t2.imul(3*rom::CURVE_B_I);

				let mut x3=FP::new_copy(&t2);
				x3.mul(&self.z);

				let mut y3=FP::new_copy(&t0);
				y3.add(&t2); y3.norm();
				self.z.mul(&t1); 
				t1.copy(&t2); t1.add(&t2); t2.add(&t1);
				t0.sub(&t2); t0.norm(); y3.mul(&t0); y3.add(&x3);
				t1.copy(&self.x); t1.mul(&self.y); 
				self.x.copy(&t0); self.x.norm(); self.x.mul(&t1); self.x.dbl();
				self.x.norm(); 
				self.y.copy(&y3); self.y.norm();

			} else {

				let mut t0=FP::new_copy(&self.x);
				let mut t1=FP::new_copy(&self.y);
				let mut t2=FP::new_copy(&self.z);
				let mut t3=FP::new_copy(&self.x);
				let mut z3=FP::new_copy(&self.z);
				let mut y3=FP::new();
				let mut x3=FP::new();
				let mut b=FP::new();

				if rom::CURVE_B_I==0 {
					b.copy(&FP::new_big(&BIG::new_ints(&rom::CURVE_B)));
				}

				t0.sqr();  //1    x^2
				t1.sqr();  //2    y^2
				t2.sqr();  //3

				t3.mul(&self.y); //4
				t3.dbl(); t3.norm();//5
				z3.mul(&self.x);   //6
				z3.dbl();  z3.norm();//7
				y3.copy(&t2); 
				
				if rom::CURVE_B_I==0 {
					y3.mul(&b); //8
				} else {
					y3.imul(rom::CURVE_B_I);
				}
				
				y3.sub(&z3); //y3.norm(); //9  ***
				x3.copy(&y3); x3.add(&y3); x3.norm();//10

				y3.add(&x3); //y3.norm();//11
				x3.copy(&t1); x3.sub(&y3); x3.norm();//12
				y3.add(&t1); y3.norm();//13
				y3.mul(&x3); //14
				x3.mul(&t3); //15
				t3.copy(&t2); t3.add(&t2); //t3.norm(); //16
				t2.add(&t3); //t2.norm(); //17

				if rom::CURVE_B_I==0 {
					z3.mul(&b); //18
				} else {
					z3.imul(rom::CURVE_B_I);
				}

				z3.sub(&t2); //z3.norm();//19
				z3.sub(&t0); z3.norm();//20  ***
				t3.copy(&z3); t3.add(&z3); //t3.norm();//21

				z3.add(&t3); z3.norm(); //22
				t3.copy(&t0); t3.add(&t0); //t3.norm(); //23
				t0.add(&t3); //t0.norm();//24
				t0.sub(&t2); t0.norm();//25

				t0.mul(&z3);//26
				y3.add(&t0); //y3.norm();//27
				t0.copy(&self.y); t0.mul(&self.z);//28
				t0.dbl(); t0.norm(); //29
				z3.mul(&t0);//30
				x3.sub(&z3); //x3.norm();//31
				t0.dbl(); t0.norm();//32
				t1.dbl(); t1.norm();//33
				z3.copy(&t0); z3.mul(&t1);//34

				self.x.copy(&x3); self.x.norm(); 
				self.y.copy(&y3); self.y.norm();
				self.z.copy(&z3); self.z.norm();

			}

        }
        if CURVETYPE==EDWARDS {
            let mut c=FP::new_copy(&self.x);
            let mut d=FP::new_copy(&self.y);
            let mut h=FP::new_copy(&self.z);
            let mut j=FP::new();
    
            self.x.mul(&self.y); self.x.dbl(); self.x.norm();
            c.sqr();
            d.sqr();
            if rom::CURVE_A == -1 {c.neg()}
            self.y.copy(&c); self.y.add(&d);
            self.y.norm();
            h.sqr(); h.dbl(); 
            self.z.copy(&self.y);
            j.copy(&self.y); j.sub(&h); j.norm();
            self.x.mul(&j);
            c.sub(&d); c.norm();
            self.y.mul(&c);
            self.z.mul(&j);
    
        //    self.x.norm();
        //    self.y.norm();
        //    self.z.norm();
        }
        if CURVETYPE==MONTGOMERY {
            let mut a=FP::new_copy(&self.x);
            let mut b=FP::new_copy(&self.x);
            let mut aa=FP::new();
            let mut bb=FP::new();
            let mut c=FP::new();
    
    
            a.add(&self.z); a.norm();
            aa.copy(&a); aa.sqr();
            b.sub(&self.z); b.norm();
            bb.copy(&b); bb.sqr();
            c.copy(&aa); c.sub(&bb); c.norm();
    
            self.x.copy(&aa); self.x.mul(&bb);
    
            a.copy(&c); a.imul((rom::CURVE_A+2)/4);
    
            bb.add(&a); bb.norm();
            self.z.copy(&bb); self.z.mul(&c);
 
        }
        return;
    }

    /* self+=Q */
    pub fn add(&mut self,Q:&ECP)
    {
    /*    if self.inf {
			self.copy(&Q);
			return;
        }
        if Q.inf {return}  */

        if CURVETYPE==WEIERSTRASS {
 
			if rom::CURVE_A==0 {
				let b=3*rom::CURVE_B_I;
				let mut t0=FP::new_copy(&self.x); 
				t0.mul(&Q.x);
				let mut t1=FP::new_copy(&self.y);
				t1.mul(&Q.y);
				let mut t2=FP::new_copy(&self.z);
				t2.mul(&Q.z);
				let mut t3=FP::new_copy(&self.x);
				t3.add(&self.y); t3.norm();
				let mut t4=FP::new_copy(&Q.x);
				t4.add(&Q.y); t4.norm();
				t3.mul(&t4);
				t4.copy(&t0); t4.add(&t1);

				t3.sub(&t4); t3.norm();
				t4.copy(&self.y);
				t4.add(&self.z); t4.norm();
				let mut x3=FP::new_copy(&Q.y);
				x3.add(&Q.z); x3.norm();

				t4.mul(&x3);
				x3.copy(&t1);
				x3.add(&t2);
	
				t4.sub(&x3); t4.norm();
				x3.copy(&self.x); x3.add(&self.z); x3.norm();
				let mut y3=FP::new_copy(&Q.x);
				y3.add(&Q.z); y3.norm();
				x3.mul(&y3);
				y3.copy(&t0);
				y3.add(&t2);
				y3.rsub(&x3); y3.norm();
				x3.copy(&t0); x3.add(&t0); 
				t0.add(&x3); t0.norm();
				t2.imul(b);

				let mut z3=FP::new_copy(&t1); z3.add(&t2); z3.norm();
				t1.sub(&t2); t1.norm(); 
				y3.imul(b);
	
				x3.copy(&y3); x3.mul(&t4); t2.copy(&t3); t2.mul(&t1); x3.rsub(&t2);
				y3.mul(&t0); t1.mul(&z3); y3.add(&t1);
				t0.mul(&t3); z3.mul(&t4); z3.add(&t0);

				self.x.copy(&x3); self.x.norm(); 
				self.y.copy(&y3); self.y.norm();
				self.z.copy(&z3); self.z.norm();
			} else {

				let mut t0=FP::new_copy(&self.x);
				let mut t1=FP::new_copy(&self.y);
				let mut t2=FP::new_copy(&self.z);
				let mut t3=FP::new_copy(&self.x);
				let mut t4=FP::new_copy(&Q.x);
				let mut z3=FP::new();
				let mut y3=FP::new_copy(&Q.x);
				let mut x3=FP::new_copy(&Q.y);
				let mut b=FP::new();

				if rom::CURVE_B_I==0 {
					b.copy(&FP::new_big(&BIG::new_ints(&rom::CURVE_B)));
				}

				t0.mul(&Q.x); //1
				t1.mul(&Q.y); //2
				t2.mul(&Q.z); //3

				t3.add(&self.y); t3.norm(); //4
				t4.add(&Q.y); t4.norm();//5
				t3.mul(&t4);//6
				t4.copy(&t0); t4.add(&t1); //t4.norm(); //7
				t3.sub(&t4); t3.norm(); //8
				t4.copy(&self.y); t4.add(&self.z); t4.norm();//9
				x3.add(&Q.z); x3.norm();//10
				t4.mul(&x3); //11
				x3.copy(&t1); x3.add(&t2); //x3.norm();//12

				t4.sub(&x3); t4.norm();//13
				x3.copy(&self.x); x3.add(&self.z); x3.norm(); //14
				y3.add(&Q.z); y3.norm();//15

				x3.mul(&y3); //16
				y3.copy(&t0); y3.add(&t2); //y3.norm();//17

				y3.rsub(&x3); y3.norm(); //18
				z3.copy(&t2); 
				

				if rom::CURVE_B_I==0 {
					z3.mul(&b); //18
				} else {
					z3.imul(rom::CURVE_B_I);
				}
				
				x3.copy(&y3); x3.sub(&z3); x3.norm(); //20
				z3.copy(&x3); z3.add(&x3); //z3.norm(); //21

				x3.add(&z3); //x3.norm(); //22
				z3.copy(&t1); z3.sub(&x3); z3.norm(); //23
				x3.add(&t1); x3.norm(); //24

				if rom::CURVE_B_I==0 {
					y3.mul(&b); //18
				} else {
					y3.imul(rom::CURVE_B_I);
				}

				t1.copy(&t2); t1.add(&t2); //t1.norm();//26
				t2.add(&t1); //t2.norm();//27

				y3.sub(&t2); //y3.norm(); //28

				y3.sub(&t0); y3.norm(); //29
				t1.copy(&y3); t1.add(&y3); //t1.norm();//30
				y3.add(&t1); y3.norm(); //31

				t1.copy(&t0); t1.add(&t0); //t1.norm(); //32
				t0.add(&t1); //t0.norm();//33
				t0.sub(&t2); t0.norm();//34
				t1.copy(&t4); t1.mul(&y3);//35
				t2.copy(&t0); t2.mul(&y3);//36
				y3.copy(&x3); y3.mul(&z3);//37
				y3.add(&t2); //y3.norm();//38
				x3.mul(&t3);//39
				x3.sub(&t1);//40
				z3.mul(&t4);//41
				t1.copy(&t3); t1.mul(&t0);//42
				z3.add(&t1); 
				self.x.copy(&x3); self.x.norm(); 
				self.y.copy(&y3); self.y.norm();
				self.z.copy(&z3); self.z.norm();

			}
        }
        if CURVETYPE==EDWARDS {
            let bb=FP::new_big(&BIG::new_ints(&rom::CURVE_B));
            let mut a=FP::new_copy(&self.z);
            let mut b=FP::new();
            let mut c=FP::new_copy(&self.x);
            let mut d=FP::new_copy(&self.y);
            let mut e=FP::new();
            let mut f=FP::new();
            let mut g=FP::new();
    
            a.mul(&Q.z);
            b.copy(&a); b.sqr();
            c.mul(&Q.x);
            d.mul(&Q.y);
    
            e.copy(&c); e.mul(&d); e.mul(&bb);
            f.copy(&b); f.sub(&e);
            g.copy(&b); g.add(&e);
    
            if rom::CURVE_A==1 {
				e.copy(&d); e.sub(&c);
            }
            c.add(&d);
    
            b.copy(&self.x); b.add(&self.y);
            d.copy(&Q.x); d.add(&Q.y); 
            b.norm(); d.norm();
            b.mul(&d);
            b.sub(&c);
            b.norm(); f.norm();
            b.mul(&f);
            self.x.copy(&a); self.x.mul(&b);
            g.norm();
            if rom::CURVE_A==1 {
				e.norm(); c.copy(&e); c.mul(&g);
            }
            if rom::CURVE_A == -1 {
				c.norm(); c.mul(&g);
            }
            self.y.copy(&a); self.y.mul(&c);
            self.z.copy(&f); self.z.mul(&g);
        }
        return;
    }

/* Differential Add for Montgomery curves. this+=Q where W is this-Q and is affine. */
	pub fn dadd(&mut self,Q: &ECP,W: &ECP) {
		let mut a=FP::new_copy(&self.x);
		let mut b=FP::new_copy(&self.x);
		let mut c=FP::new_copy(&Q.x);
		let mut d=FP::new_copy(&Q.x);
		let mut da=FP::new();
		let mut cb=FP::new();
			
		a.add(&self.z);
		b.sub(&self.z);

		c.add(&Q.z);
		d.sub(&Q.z);

		a.norm(); d.norm();

		da.copy(&d); da.mul(&a);

		c.norm(); b.norm();

		cb.copy(&c); cb.mul(&b);

		a.copy(&da); a.add(&cb); a.norm(); a.sqr();
		b.copy(&da); b.sub(&cb); b.norm(); b.sqr();

		self.x.copy(&a);
		self.z.copy(&W.x); self.z.mul(&b);
	}

/* self-=Q */
	pub fn sub(&mut self,Q:&ECP) {
		let mut NQ=ECP::new(); NQ.copy(Q);
		NQ.neg();
		self.add(&NQ);
	}

/* constant time multiply by small integer of length bts - use ladder */
	pub fn pinmul(&self,e: i32,bts: i32) -> ECP {	
		if CURVETYPE==MONTGOMERY {
			return self.mul(&mut BIG::new_int(e as isize));
		} else {
			let mut P=ECP::new();
			let mut R0=ECP::new();
			let mut R1=ECP::new(); R1.copy(&self);

			for i in (0..bts).rev() {
				let b=((e>>i)&1) as isize;
				P.copy(&R1);
				P.add(&mut R0);
				R0.cswap(&mut R1,b);
				R1.copy(&P);
				R0.dbl();
				R0.cswap(&mut R1,b);
			}
			P.copy(&R0);
			P.affine();
			return P;
		}
	}

/* return e.self */

	pub fn mul(&self,e:&BIG) -> ECP {
		if e.iszilch() || self.is_infinity() {return ECP::new()}
		let mut P=ECP::new();
		if CURVETYPE==MONTGOMERY {
/* use Ladder */
			let mut D=ECP::new();
			let mut R0=ECP::new(); R0.copy(&self);
			let mut R1=ECP::new(); R1.copy(&self);
			R1.dbl();
			D.copy(&self); D.affine();
			let nb=e.nbits();

			for i in (0..nb-1).rev() {
				let b=e.bit(i);
				P.copy(&R1);
				P.dadd(&mut R0,&D);
				R0.cswap(&mut R1,b);
				R1.copy(&P);
				R0.dbl();
				R0.cswap(&mut R1,b);
			}
			P.copy(&R0)
		} else {
// fixed size windows 
			let mut mt=BIG::new();
			let mut t=BIG::new();
			let mut Q=ECP::new();
			let mut C=ECP::new();

		 	let mut W:[ECP;8]=[ECP::new(),ECP::new(),ECP::new(),ECP::new(),ECP::new(),ECP::new(),ECP::new(),ECP::new()];

		 	const CT:usize=1+(big::NLEN*(big::BASEBITS as usize)+3)/4;
			let mut w:[i8;CT]=[0;CT];

		//	self.affine();

			Q.copy(&self);
			Q.dbl();

			W[0].copy(&self);

			for i in 1..8 {
				C.copy(&W[i-1]);
				W[i].copy(&C);
				W[i].add(&mut Q);
			}

// make exponent odd - add 2P if even, P if odd 
			t.copy(&e);
			let s=t.parity();
			t.inc(1); t.norm(); let ns=t.parity(); mt.copy(&t); mt.inc(1); mt.norm();
			t.cmove(&mt,s);
			Q.cmove(&self,ns);
			C.copy(&Q);

			let nb=1+(t.nbits()+3)/4;

// convert exponent to signed 4-bit window 
			for i in 0..nb {
				w[i]=(t.lastbits(5)-16) as i8;
				t.dec(w[i] as isize); t.norm();
				t.fshr(4);	
			}
			w[nb]=t.lastbits(5) as i8;

			P.copy(&W[((w[nb] as usize)-1)/2]); 
			for i in (0..nb).rev() {
				Q.selector(&W,w[i] as i32);
				P.dbl();
				P.dbl();
				P.dbl();
				P.dbl();
				P.add(&mut Q);
			}
			P.sub(&mut C); /* apply correction */
		}
		P.affine();
		return P;
	}

/* Return e.this+f.Q */

	pub fn mul2(&self,e: &BIG,Q: &ECP,f: &BIG) -> ECP {
		let mut te=BIG::new();
		let mut tf=BIG::new();
		let mut mt=BIG::new();
		let mut S=ECP::new();
		let mut T=ECP::new();
		let mut C=ECP::new();

		let mut W:[ECP;8]=[ECP::new(),ECP::new(),ECP::new(),ECP::new(),ECP::new(),ECP::new(),ECP::new(),ECP::new()];

		const CT:usize=1+(big::NLEN*(big::BASEBITS as usize)+1)/2;
		let mut w: [i8;CT]=[0;CT];		

	//	self.affine();
	//	Q.affine();

		te.copy(e);
		tf.copy(f);

// precompute table 

		W[1].copy(&self); W[1].sub(Q);
		W[2].copy(&self); W[2].add(Q);
		S.copy(&Q); S.dbl();
		C.copy(&W[1]); W[0].copy(&C); W[0].sub(&mut S); // copy to C is stupid Rust thing..
		C.copy(&W[2]); W[3].copy(&C); W[3].add(&mut S);
		T.copy(&self); T.dbl();
		C.copy(&W[1]); W[5].copy(&C); W[5].add(&mut T);
		C.copy(&W[2]); W[6].copy(&C); W[6].add(&mut T);
		C.copy(&W[5]); W[4].copy(&C); W[4].sub(&mut S);
		C.copy(&W[6]); W[7].copy(&C); W[7].add(&mut S);

// if multiplier is odd, add 2, else add 1 to multiplier, and add 2P or P to correction 

		let mut s=te.parity();
		te.inc(1); te.norm(); let mut ns=te.parity(); mt.copy(&te); mt.inc(1); mt.norm();
		te.cmove(&mt,s);
		T.cmove(&self,ns);
		C.copy(&T);

		s=tf.parity();
		tf.inc(1); tf.norm(); ns=tf.parity(); mt.copy(&tf); mt.inc(1); mt.norm();
		tf.cmove(&mt,s);
		S.cmove(&Q,ns);
		C.add(&mut S);

		mt.copy(&te); mt.add(&tf); mt.norm();
		let nb=1+(mt.nbits()+1)/2;

// convert exponent to signed 2-bit window 
		for i in 0..nb {
			let a=te.lastbits(3)-4;
			te.dec(a); te.norm();
			te.fshr(2);
			let b=tf.lastbits(3)-4;
			tf.dec(b); tf.norm();
			tf.fshr(2);
			w[i]=(4*a+b) as i8;
		}
		w[nb]=(4*te.lastbits(3)+tf.lastbits(3)) as i8;
		S.copy(&W[((w[nb] as usize)-1)/2]);  

		for i in (0..nb).rev() {
			T.selector(&W,w[i] as i32);
			S.dbl();
			S.dbl();
			S.add(&mut T);
		}
		S.sub(&mut C); /* apply correction */
		S.affine();
		return S;
	}

	pub fn cfp(&mut self) {
		let cf=rom::CURVE_COF_I;
		if cf==1 {return}
		if cf==4 {
			self.dbl(); self.dbl();
			self.affine();
			return;
		} 
		if cf==8 {
			self.dbl(); self.dbl(); self.dbl();
			self.affine();
			return;
		}
		let c=BIG::new_ints(&rom::CURVE_COF);
		let P=self.mul(&c);
		self.copy(&P);	
	}


#[allow(non_snake_case)]
	pub fn mapit(h: &[u8]) -> ECP {
		let mut q=BIG::new_ints(&rom::MODULUS);
		let mut x=BIG::frombytes(h);
		x.rmod(&mut q);
		let mut P:ECP;

		loop {
			loop {
				if CURVETYPE!=MONTGOMERY {
					P=ECP::new_bigint(&x,0);
				} else {
					P=ECP::new_big(&x);
				}
				x.inc(1); x.norm();
				if !P.is_infinity() {break}
			}
			P.cfp();
			if !P.is_infinity() {break}
		}
			
		return P;	
	}

	pub fn generator() -> ECP {
		let G:ECP;

		let gx=BIG::new_ints(&rom::CURVE_GX);
	
		if CURVETYPE!=MONTGOMERY {
			let gy=BIG::new_ints(&rom::CURVE_GY);
			G=ECP::new_bigs(&gx,&gy);
		} else {
			G=ECP::new_big(&gx);
		}
		return G;		
	}

}
/*
fn main()
{
	let mut E=ECP::new();

	let mut W:[&ECP;8]=[&ECP::new(),&ECP::new(),&ECP::new(),&ECP::new(),&ECP::new(),&ECP::new(),&ECP::new(),&ECP::new()];

	let mut gx=BIG::new_ints(&rom::CURVE_GX);
	let mut gy=BIG::new();
	let mut P=ECP::new();

	if CURVETYPE!=MONTGOMERY {gy.copy(&BIG::new_ints(&rom::CURVE_GY))}
	let mut r=BIG::new_ints(&rom::CURVE_ORDER);

	//r.dec(7);
	
	println!("gx= {}",gx.tostring());

	if CURVETYPE!=MONTGOMERY {
		println!("gy= {}",gy.tostring());
	}	

	if CURVETYPE!=MONTGOMERY {
		P.copy(&ECP::new_bigs(&gx,&gy))}
	else  {P.copy(&ECP::new_big(&gx))}

	println!("P= {}",P.tostring());		

	let mut R=P.mul(&mut r);
		//for i in 0..10000	(R=P.mul(r));
	
	println!("R= {}",R.tostring());

}
*/
