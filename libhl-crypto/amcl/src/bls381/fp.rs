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

use bls381::big;
use bls381::big::BIG;
use bls381::dbig::DBIG;
use bls381::rom;
use arch::Chunk;

//#[cfg(D32)]
//use arch::DChunk;

#[derive(Copy, Clone)]
pub struct FP {
 	pub x:BIG,
    pub xes:i32
}

pub const NOT_SPECIAL:usize =0;
pub const PSEUDO_MERSENNE:usize=1;
pub const MONTGOMERY_FRIENDLY:usize=2;
pub const GENERALISED_MERSENNE:usize=3;

pub const MODBITS:usize = 381; /* Number of bits in Modulus */
pub const MOD8: usize = 3;  /* Modulus mod 8 */
pub const MODTYPE:usize=NOT_SPECIAL;

pub const FEXCESS:i32 = ((1 as i32)<<25);
pub const OMASK:Chunk = (-1)<<(MODBITS%big::BASEBITS);
pub const TBITS:usize=MODBITS%big::BASEBITS; // Number of active bits in top word
pub const TMASK:Chunk=(1<<TBITS)-1;


impl FP {

/* Constructors */
	pub fn new() -> FP {
		FP {
				x: BIG::new(),
                xes:1
            }
	}

	pub fn new_int(a:isize) -> FP {
		let mut f=FP::new(); 
		f.x.inc(a);
		f.nres();
		return f;		
	}

	pub fn new_copy(y:&FP) -> FP {
		let mut f=FP::new(); 
		f.x.copy(&(y.x));
        f.xes=y.xes;
		return f;
	}

	pub fn new_big(y:&BIG) -> FP {
		let mut f=FP::new(); 
		f.x.copy(y);
        f.nres();
		return f;		
	}

    pub fn nres(&mut self) {
        if MODTYPE != PSEUDO_MERSENNE && MODTYPE != GENERALISED_MERSENNE {
            let r=BIG::new_ints(&rom::R2MODP);
            let mut d=BIG::mul(&(self.x),&r);
            self.x.copy(&FP::modulo(&mut d));
            self.xes=2;
        } else {
            self.xes=1;
        }

    }

/* convert back to regular form */
    pub fn redc(&mut self) -> BIG {
        if MODTYPE != PSEUDO_MERSENNE && MODTYPE != GENERALISED_MERSENNE {
            let mut d=DBIG::new_scopy(&(self.x));
            return FP::modulo(&mut d);
        } else {
            let r=BIG::new_copy(&(self.x));
            return r;
        }
    }


/* reduce a DBIG to a BIG using the appropriate form of the modulus */
/* dd */
    pub fn modulo(d: &mut DBIG) -> BIG {
    
        if MODTYPE==PSEUDO_MERSENNE {
            let mut b=BIG::new();
            let mut t=d.split(MODBITS);
            b.dcopy(&d);
            let v=t.pmul(rom::MCONST as isize);

            t.add(&b);
            t.norm();


            let tw=t.w[big::NLEN-1];
            t.w[big::NLEN-1] &= TMASK;
            t.w[0]+=rom::MCONST*((tw>>TBITS)+(v<<(big::BASEBITS-TBITS)));
            t.norm();
            return t;
        }
    
        if MODTYPE==MONTGOMERY_FRIENDLY
        {
            let mut b=BIG::new();
            for i in 0 ..big::NLEN {
                let x=d.w[i];

                let tuple=BIG::muladd(x,rom::MCONST-1,x,d.w[big::NLEN+i-1]);
                d.w[big::NLEN+i]+=tuple.0; d.w[big::NLEN+i-1]=tuple.1;
            }
    
            b.zero();
    
            for i in 0 ..big::NLEN {
                b.w[i]=d.w[big::NLEN+i];
            }
            b.norm();
            return b;
        }
            
        if MODTYPE==GENERALISED_MERSENNE
        { // GoldiLocks Only
            let mut b=BIG::new();            
            let t=d.split(MODBITS);
            let rm2=(MODBITS/2) as usize;
            b.dcopy(&d);
            b.add(&t);
            let mut dd=DBIG::new_scopy(&t);
            dd.shl(rm2);
            
            let mut tt=dd.split(MODBITS);
            let lo=BIG::new_dcopy(&dd);
            b.add(&tt);
            b.add(&lo);
            b.norm();
            tt.shl(rm2);
            b.add(&tt);
            
            let carry=b.w[big::NLEN-1]>>TBITS;
            b.w[big::NLEN-1]&=TMASK;
            b.w[0]+=carry;
            
            b.w[(224/big::BASEBITS) as usize]+=carry<<(224%big::BASEBITS);
            b.norm();
            return b;
        }
       
        if MODTYPE==NOT_SPECIAL {
            let m = BIG::new_ints(&rom::MODULUS);              
            return BIG::monty(&m,rom::MCONST,d);
        }     
        return BIG::new();
    }

   /* convert to string */
	pub fn tostring(&mut self) -> String {
        let s=self.redc().tostring();
        return s;
    }

/* reduce this mod Modulus */
    pub fn reduce(&mut self) {
  		let p = BIG::new_ints(&rom::MODULUS);      	
        self.x.rmod(&p);
        self.xes=1;
    }
    
/* test this=0? */
    pub fn iszilch(&mut self) -> bool {
        self.reduce();
        return self.x.iszilch();
    }
    
/* copy from FP b */
    pub fn copy(&mut self,b: &FP) {
        self.x.copy(&(b.x));
        self.xes=b.xes;
    }
    
/* copy from BIG b */
    pub fn bcopy(&mut self,b: &BIG) {
        self.x.copy(&b);
        self.nres();
    }

/* set this=0 */
    pub fn zero(&mut self) {
        self.x.zero();
        self.xes=1;
    }
    
/* set this=1 */
    pub fn one(&mut self) {
        self.x.one(); self.nres()
    }
    
/* normalise this */
    pub fn norm(&mut self) {
        self.x.norm();
    }
/* swap FPs depending on d */
    pub fn cswap(&mut self,b: &mut FP,d: isize) {
        self.x.cswap(&mut (b.x),d);
        let mut c=d as i32;
        c=!(c-1);
        let t=c&(self.xes^b.xes);
        self.xes^=t;
        b.xes^=t;
    }
    
/* copy FPs depending on d */
    pub fn cmove(&mut self,b: &FP,d: isize) {
        self.x.cmove(&(b.x),d);
        let c=d as i32;
        self.xes^=(self.xes^b.xes)&(-c);
    }

/* this*=b mod Modulus */
    pub fn mul(&mut self,b: &FP)
    {
        if (self.xes as i64)*(b.xes as i64) > FEXCESS as i64 {self.reduce()}

        let mut d=BIG::mul(&(self.x),&(b.x));
        self.x.copy(&FP::modulo(&mut d));
        self.xes=2;
    }

    fn logb2(w: u32) -> usize {
        let mut v=w;
        v |= v >> 1;
        v |= v >> 2;
        v |= v >> 4;
        v |= v >> 8;
        v |= v >> 16;

        v = v - ((v >> 1) & 0x55555555);                 
        v = (v & 0x33333333) + ((v >> 2) & 0x33333333);  
        let r= ((   ((v + (v >> 4)) & 0xF0F0F0F).wrapping_mul(0x1010101)) >> 24) as usize;
        return r;    
    }

/* this = -this mod Modulus */
    pub fn neg(&mut self) {
  		let mut p = BIG::new_ints(&rom::MODULUS);   
        let sb=FP::logb2((self.xes-1) as u32);
    
        p.fshl(sb);
        self.x.rsub(&p);
        self.xes=1<<(sb as i32);
        if self.xes>FEXCESS {self.reduce()}

    }

    /* this*=c mod Modulus, where c is a small int */
    pub fn imul(&mut self,c: isize) {
        let mut cc=c;
    //    self.norm();
        let mut s=false;
        if cc<0 {
            cc = -cc;
            s=true;
        }

        if MODTYPE==PSEUDO_MERSENNE || MODTYPE==GENERALISED_MERSENNE {
            let mut d=self.x.pxmul(cc);
            self.x.copy(&FP::modulo(&mut d));
            self.xes=2
        } else {
            if self.xes*(cc as i32) <= FEXCESS {
                self.x.pmul(cc);
                self.xes*=cc as i32;
            } else {
                let n=FP::new_int(cc);
                self.mul(&n);
            }

        }

        if s {self.neg(); self.norm();}
    }

/* self*=self mod Modulus */
    pub fn sqr(&mut self) {
    //    self.norm();
        if (self.xes as i64)*(self.xes as i64) > FEXCESS as i64 {self.reduce()}


        let mut d=BIG::sqr(&(self.x));
        self.x.copy(&FP::modulo(&mut d));
        self.xes=2
    }

/* self+=b */
    pub fn add(&mut self,b: &FP) {
        self.x.add(&(b.x));
        self.xes+=b.xes;
        if self.xes>FEXCESS {self.reduce()}
    }

/* self+=self */
    pub fn dbl(&mut self) {
        self.x.dbl();
        self.xes+=self.xes;        
        if self.xes>FEXCESS {self.reduce()}
    }
    
/* self-=b */
    pub fn sub(&mut self,b: &FP)
    {
        let mut n=FP::new_copy(b);
        n.neg();
        self.add(&n);
    }    

/* self=b-self */
    pub fn rsub(&mut self,b: &FP)
    {
        self.neg();
        self.add(&b);
    }  

/* self/=2 mod Modulus */
    pub fn div2(&mut self) {
    //    self.x.norm();
        if self.x.parity()==0 {
        	self.x.fshr(1);
        } else {
  			let p = BIG::new_ints(&rom::MODULUS);           	
            self.x.add(&p);
            self.x.norm();
            self.x.fshr(1);
        }
    }
/* self=1/self mod Modulus */
    pub fn inverse(&mut self) {
/*        
  		let mut p = BIG::new_ints(&rom::MODULUS);      	
        let mut r=self.redc();
        r.invmodp(&mut p);
        self.x.copy(&r);
        self.nres();
*/
        let mut m2 = BIG::new_ints(&rom::MODULUS); 
        m2.dec(2); m2.norm();
        let inv=self.pow(&mut m2);
        self.copy(&inv);          
    }

/* return TRUE if self==a */
    pub fn equals(&mut self,a: &mut FP) -> bool {
        a.reduce();
        self.reduce();
        if BIG::comp(&(a.x),&self.x)==0 {return true}
        return false;
    }   


/* return self^e mod Modulus */
    pub fn pow(&mut self,e: &mut BIG) -> FP {
        let mut tb:[FP;16]=[FP::new(),FP::new(),FP::new(),FP::new(),FP::new(),FP::new(),FP::new(),FP::new(),FP::new(),FP::new(),FP::new(),FP::new(),FP::new(),FP::new(),FP::new(),FP::new()];
        const CT:usize=1+(big::NLEN*(big::BASEBITS as usize)+3)/4;
        let mut w:[i8;CT]=[0;CT];

        self.norm();
        let mut t=BIG::new_copy(e);
        t.norm();
        let nb=1+(t.nbits()+3)/4;

        for i in 0..nb {
            let lsbs=t.lastbits(4);
            t.dec(lsbs);
            t.norm();
            w[i]=lsbs as i8;
            t.fshr(4);
        }
        tb[0].one();
        tb[1].copy(&self);

        let mut c=FP::new();
        for i in 2..16 {
            c.copy(&tb[i-1]);
            tb[i].copy(&c);
            tb[i].mul(&self);
        }
        let mut r=FP::new_copy(&tb[w[nb-1] as usize]);
        for i in  (0..nb-1).rev() {
            r.sqr();
            r.sqr();
            r.sqr();
            r.sqr();
            r.mul(&tb[w[i] as usize])
        }
        r.reduce();
        return r;
}

/* return self^e mod Modulus 
    pub fn pow(&mut self,e: &mut BIG) -> FP {
      	let p = BIG::new_ints(&rom::MODULUS);   	
        let mut r=FP::new_int(1);
        e.norm();
        self.x.norm();
		let mut m=FP::new_copy(self);
        loop {
            let bt=e.parity();
            e.fshr(1);
            if bt==1 {r.mul(&m)}
            if e.iszilch() {break}
            m.sqr();
        }
        r.x.rmod(&p);
        return r;
    } */

/* return sqrt(this) mod Modulus */
    pub fn sqrt(&mut self) -> FP {
        self.reduce();
      	let mut p = BIG::new_ints(&rom::MODULUS);  
        if MOD8==5 {
            p.dec(5); p.norm(); p.shr(3);
            let mut i=FP::new_copy(self); i.x.shl(1);
            let v=i.pow(&mut p);
            i.mul(&v); i.mul(&v);
            i.x.dec(1);
            let mut r=FP::new_copy(self);
            r.mul(&v); r.mul(&i);
            r.reduce();
            return r;
        }
        else
        {
            p.inc(1); p.norm(); p.shr(2);
            return self.pow(&mut p);
        }
    }
/* return jacobi symbol (this/Modulus) */
    pub fn jacobi(&mut self) -> isize
    {
     	let mut p = BIG::new_ints(&rom::MODULUS);      	
        let mut w=self.redc();
        return w.jacobi(&mut p);
    }

}
/*
fn main() {
    let p = BIG::new_ints(&rom::MODULUS);  
	let mut e = BIG::new_copy(&p);
	e.dec(1);

    let mut x = FP::new_int(3);
    let mut s=x.pow(&mut e);

    println!("s= {}",s.tostring());
}
*/
