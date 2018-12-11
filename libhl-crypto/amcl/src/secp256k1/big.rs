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

use arch;
use arch::Chunk;

//#[cfg(D32)]
use arch::DChunk;

use secp256k1::dbig::DBIG;
use rand::RAND;

pub const MODBYTES:usize = 32;
pub const BASEBITS:usize = 56;

pub const NLEN: usize = (1+((8*MODBYTES-1)/BASEBITS));
pub const DNLEN: usize = 2*NLEN;
pub const BMASK: Chunk= ((1<<BASEBITS)-1);
pub const HBITS: usize=(BASEBITS/2);
pub const HMASK: Chunk= ((1<<HBITS)-1);
pub const NEXCESS:isize = (1<<((arch::CHUNK)-BASEBITS-1));
pub const BIGBITS:usize = (MODBYTES*8);


#[derive(Copy)]
pub struct BIG {
    pub w: [Chunk; NLEN]
}

impl Clone for BIG {
    fn clone(&self) -> BIG { *self }
}
/*
#[derive(Copy, Clone)]
pub struct BIG {
    pub w: [Chunk; NLEN]
}
*/

impl BIG {

   pub fn new() -> BIG {
        BIG {
        	w: [0; NLEN]
         }
    }

    pub fn new_int(x:isize) -> BIG {
    	let mut s= BIG::new();
    	s.w[0]=x as Chunk;
    	return s;
    }

    pub fn new_ints(a:&[Chunk]) -> BIG {
    	let mut s= BIG::new();
    	for i in 0..NLEN {s.w[i]=a[i]}
    	return s;
    }

    pub fn new_copy(y:&BIG) -> BIG {
    	let mut s= BIG::new();   
    	for i in 0..NLEN {s.w[i]=y.w[i]}
    	return s;	
    }

    pub fn new_big(y:&BIG) -> BIG {
        let mut s= BIG::new();   
        for i in 0..NLEN {s.w[i]=y.w[i]}
        return s;   
    }

    pub fn new_dcopy(y:&DBIG) -> BIG {
    	let mut s= BIG::new();   
    	for i in 0..NLEN {s.w[i]=y.w[i]}
    	return s;	
    } 

	pub fn get(&self,i:usize) -> Chunk {
		return self.w[i]; 
	}

	pub fn set(&mut self,i:usize,x:Chunk) {
		self.w[i]=x;	
	}

	pub fn xortop(&mut self,x:Chunk) {
		self.w[NLEN-1]^=x;
	}

	pub fn ortop(&mut self,x:Chunk) {
		self.w[NLEN-1]|=x;
	}

/* test for zero */
	pub fn iszilch(&self) -> bool {
		for i in 0 ..NLEN {
			if self.w[i]!=0 {return false}
		}
		return true; 
	}

/* set to zero */
	pub fn zero(&mut self) {
		for i in 0 ..NLEN {
			self.w[i]=0
		}
	}

/* Test for equal to one */
	pub fn isunity(&self) -> bool {
		for i in 0 ..NLEN {
			if self.w[i]!=0 {return false}
		}
		if self.w[0]!=1 {return false}
		return true;
	}

/* set to one */
	pub fn one(&mut self) {
		self.w[0]=1;
		for i in 1 ..NLEN {
			self.w[i]=0;
		}
	}

/* Copy from another BIG */
	pub fn copy(&mut self,x: &BIG) {
		for i in 0 ..NLEN {
			self.w[i]=x.w[i]
		}
	}

    pub fn dcopy(&mut self,x: &DBIG)
    {
        for i in 0 ..NLEN {self.w[i] = x.w[i]}
    }


/* Get top and bottom half of =x*y+c+r */
//#[cfg(D32)]
    pub fn muladd(a: Chunk,b: Chunk,c: Chunk,r: Chunk) -> (Chunk,Chunk) {
        let prod:DChunk = (a as DChunk)*(b as DChunk)+(c as DChunk)+(r as DChunk);
        let bot=(prod&(BMASK as DChunk)) as Chunk;
        let top=(prod>>BASEBITS) as Chunk;   
        return (top,bot);     
    }

/*
#[cfg(D64)]
    pub fn muladd(a: Chunk,b: Chunk,c: Chunk,r: Chunk) -> (Chunk,Chunk) {
        let x0=a&HMASK;
        let x1=a>>HBITS;
        let y0=b&HMASK;
        let y1=b>>HBITS;
        let mut bot=x0*y0;
        let mut top=x1*y1;
        let mid=x0*y1+x1*y0;
        let u0=mid&HMASK;
        let u1=mid>>HBITS;
        bot+= u0<<HBITS;
        bot+=c; bot+=r;
        top+=u1;
        let carry=bot>>BASEBITS;
        bot&=BMASK;
        top+=carry;
        return (top,bot);
    }
*/

/* normalise BIG - force all digits < 2^BASEBITS */
    pub fn norm(&mut self) -> Chunk
    {
        let mut carry=0 as Chunk;
        for i in 0 ..NLEN-1 {
            let d=self.w[i]+carry;
            self.w[i]=d&BMASK;
            carry=d>>BASEBITS;
        }
        self.w[NLEN-1]+=carry;
        return (self.w[NLEN-1]>>((8*MODBYTES)%BASEBITS)) as Chunk;
    }

/* Conditional swap of two bigs depending on d using XOR - no branches */
	pub fn cswap(&mut self,b: &mut BIG,d: isize) {
		let mut c= d as Chunk;
		c=!(c-1);
		for i in 0 ..NLEN {
			let t=c&(self.w[i]^b.w[i]);
			self.w[i]^=t;
			b.w[i]^=t;
		}
	}

	pub fn cmove(&mut self,g:&BIG,d: isize) {
		let b= -d as Chunk;
		for i in 0 ..NLEN {
			self.w[i]^=(self.w[i]^g.w[i])&b;
		}
	}

/* Shift right by less than a word */
	pub fn fshr(&mut self, k: usize) -> isize {
		let n = k;
		let w=self.w[0]&((1<<n)-1); /* shifted out part */
		for i in 0 ..NLEN-1 {
			self.w[i]=(self.w[i]>>k)|((self.w[i+1]<<(BASEBITS-n))&BMASK);
		}
		self.w[NLEN-1]=self.w[NLEN-1]>>k;
		return w as isize;
	}

 /* general shift right */
	pub fn shr(&mut self,k:usize) {
		let n=k%BASEBITS;
		let m=k/BASEBITS;
		for i in 0 ..NLEN-m-1 {
			self.w[i]=(self.w[m+i]>>n)|((self.w[m+i+1]<<(BASEBITS-n))&BMASK)
		}
		self.w[NLEN-m-1]=self.w[NLEN-1]>>n;
		for i in NLEN-m ..NLEN 
			{self.w[i]=0}
	}	

/* Shift right by less than a word */
	pub fn fshl(&mut self,k:usize) -> isize {
		let n=k;
		self.w[NLEN-1]=((self.w[NLEN-1]<<n))|(self.w[NLEN-2]>>(BASEBITS-n));
		for i in (1 ..NLEN-1).rev() {
			self.w[i]=((self.w[i]<<k)&BMASK)|(self.w[i-1]>>(BASEBITS-n));
		}
		self.w[0]=(self.w[0]<<n)&BMASK;
		return (self.w[NLEN-1]>>((8*MODBYTES)%BASEBITS)) as isize /* return excess - only used in ff.c */
	}

/* general shift left */
	pub fn shl(&mut self,k: usize) {
		let n=k%BASEBITS;
		let m=k/BASEBITS;

		self.w[NLEN-1]=self.w[NLEN-1-m]<<n;
		if NLEN>=m+2 {self.w[NLEN-1]|=self.w[NLEN-m-2]>>(BASEBITS-n)}
		for i in (m+1 ..NLEN-1).rev() {
			self.w[i]=((self.w[i-m]<<n)&BMASK)|(self.w[i-m-1]>>(BASEBITS-n));
		}
		self.w[m]=(self.w[0]<<n)&BMASK; 
		for i in 0 ..m {self.w[i]=0}
	}

/* return number of bits */
	pub fn nbits(&self) -> usize {
		let mut k=NLEN-1;
        let mut s=BIG::new_copy(&self);        
		s.norm();
		while (k as isize)>=0 && s.w[k]==0 {k=k.wrapping_sub(1)}
		if (k as isize) <0 {return 0}
		let mut bts=BASEBITS*k;
		let mut c=s.w[k];
		while c!=0 {c/=2; bts+=1;}
		return bts;
	}

/* Convert to Hex String */
	pub fn tostring(&mut self) -> String {
		let mut s = String::new();
		let mut len=self.nbits();

		if len%4==0 {
			len/=4;
		} else {
			len/=4;
			len+=1;
		}
		let mb=(MODBYTES*2) as usize;
		if len<mb {len=mb}

		for i in (0 ..len).rev() {
			let mut b=BIG::new_copy(&self);
			b.shr(i*4);
			s=s + &format!("{:X}", b.w[0]&15);
		}
		return s;
	}	

    pub fn add(&mut self,r:&BIG) {
		for i in 0 ..NLEN {
			self.w[i]+=r.w[i] 
		}
	}

    pub fn or(&mut self,r:&BIG) {
        for i in 0 ..NLEN {
            self.w[i]|=r.w[i] 
        }
    }

    pub fn dbl(&mut self) {
        for i in 0 ..NLEN {
            self.w[i]+=self.w[i]
        }        
    }

/* return this+x */
	pub fn plus(&self,x: &BIG) -> BIG {
		let mut s=BIG::new();
		for i in 0 ..NLEN {
			s.w[i]=self.w[i]+x.w[i];
		}
		return s;
	}

    pub fn inc(&mut self,x:isize) {
    	self.norm();
    	self.w[0]+=x as Chunk; 
    }

//    pub fn incl(&mut self,x:Chunk) {
//        self.norm();
//        self.w[0]+=x; 
//    }

/* return self-x */
	pub fn minus(&self,x:& BIG) -> BIG {
		let mut d=BIG::new();
		for i in 0 ..NLEN {
			d.w[i]=self.w[i]-x.w[i];
		}
		return d;
	}

/* self-=x */
	pub fn sub(&mut self,x:&BIG) {
		for i in 0 ..NLEN {
			self.w[i]-=x.w[i]; 
		}
	} 

/* reverse subtract this=x-this */ 
	pub fn rsub(&mut self,x:&BIG) {
		for i in 0 ..NLEN {
			self.w[i]=x.w[i]-self.w[i] 
		}
	} 

/* self-=x, where x is int */
	pub fn dec(&mut self,x:isize) {
		self.norm();
		self.w[0]-= x as Chunk;
	} 

/* self*=x, where x is small int<NEXCESS */
	pub fn imul(&mut self,c: isize) {
		for i in 0 ..NLEN { 
			self.w[i]*=c as Chunk;
		}
	}

/* convert this BIG to byte array */
	pub fn tobytearray(&mut self,b: &mut [u8],n:usize) {
		self.norm();
		let mut c=BIG::new_copy(self);

		for i in (0 ..(MODBYTES as usize)).rev() {
			b[i+n]=(c.w[0]&0xff) as u8;
			c.fshr(8);
		}
	}

/* convert from byte array to BIG */
	pub fn frombytearray(b: &[u8],n:usize) -> BIG {
		let mut m=BIG::new();
		for i in 0 ..(MODBYTES as usize) {
			m.fshl(8); m.w[0]+=(b[i+n]&0xff) as Chunk;
		}
		return m; 
	}

	pub fn tobytes(&mut self,b: &mut [u8]) {
		self.tobytearray(b,0)
	}

	pub fn frombytes(b: &[u8]) -> BIG {
		return BIG::frombytearray(b,0)
	}


/* self*=x, where x is >NEXCESS */
    pub fn pmul(&mut self,c: isize) -> Chunk {
        let mut carry=0 as Chunk;
        //self.norm();
        for i in 0 ..NLEN {
            let ak=self.w[i];
            let tuple=BIG::muladd(ak,c as Chunk,carry,0 as Chunk);
            carry=tuple.0; self.w[i]=tuple.1;
        }
        return carry;
    }  

/* self*=c and catch overflow in DBIG */
    pub fn pxmul(&mut self,c: isize) -> DBIG
    {
        let mut m=DBIG::new();
        let mut carry=0 as Chunk;
        for j in 0 ..NLEN {
            let tuple=BIG::muladd(self.w[j],c as Chunk,carry,m.w[j]);
            carry=tuple.0; m.w[j]=tuple.1; 
        }
        m.w[NLEN]=carry;
        return m;
    }

/* divide by 3 */
    pub fn div3(&mut self) -> Chunk
    {
        let mut carry=0 as Chunk;
        self.norm();
        let base=1<<BASEBITS;
        for i in (0 ..NLEN).rev() {
            let ak=carry*base+self.w[i];
            self.w[i]=ak/3;
            carry=ak%3;
        }
        return carry;
    }

/* return a*b where result fits in a BIG */
    pub fn smul(a: &BIG,b: &BIG) -> BIG {
        let mut c=BIG::new();
        for i in 0 ..NLEN {
            let mut carry=0 as Chunk; 
            for j in 0 ..NLEN {
                if i+j<NLEN {
                    let tuple=BIG::muladd(a.w[i],b.w[j],carry,c.w[i+j]);
                    carry=tuple.0; c.w[i+j]=tuple.1;
                }
            }
        }
        return c;
    }

/* Compare a and b, return 0 if a==b, -1 if a<b, +1 if a>b. Inputs must be normalised */
    pub fn comp(a: &BIG,b: &BIG) -> isize {
        for i in (0 ..NLEN).rev() {
            if a.w[i]==b.w[i] {continue}
            if a.w[i]>b.w[i] {return 1}
            else  {return -1}
        }
        return 0;
    }

/* set x = x mod 2^m */
    pub fn mod2m(&mut self,m: usize)
    {
        let wd=m/BASEBITS;
        let bt=m%BASEBITS;
        let msk=(1<<bt)-1;
        self.w[wd]&=msk;
        for i in wd+1 ..NLEN {self.w[i]=0}
    }

/* Arazi and Qi inversion mod 256 */
    pub fn invmod256(a: isize) -> isize {
        let mut t1:isize=0;
        let mut c=(a>>1)&1;
        t1+=c;
        t1&=1;
        t1=2-t1;
        t1<<=1;
        let mut u=t1+1;
    
    // i=2
        let mut b=a&3;
        t1=u*b; t1>>=2;
        c=(a>>2)&3;
        let mut t2=(u*c)&3;
        t1+=t2;
        t1*=u; t1&=3;
        t1=4-t1;
        t1<<=2;
        u+=t1;
    
    // i=4
        b=a&15;
        t1=u*b; t1>>=4;
        c=(a>>4)&15;
        t2=(u*c)&15;
        t1+=t2;
        t1*=u; t1&=15;
        t1=16-t1;
        t1<<=4;
        u+=t1;
    
        return u;
    }

/* return parity */
    pub fn parity(&self) -> isize {
        return (self.w[0]%2) as isize;
    }

/* return n-th bit */
    pub fn bit(&self,n: usize) -> isize {
        if (self.w[n/(BASEBITS as usize)]&(1<<(n%BASEBITS)))>0 {return 1;}
        else {return 0;}
    }

/* return n last bits */
    pub fn lastbits(&mut self,n: usize) -> isize
    {
        let msk =  ((1<<n)-1) as Chunk; 
        self.norm();
        return (self.w[0]&msk) as isize;
    }

/* a=1/a mod 2^256. This is very fast! */
    pub fn invmod2m(&mut self) {
        let mut u=BIG::new();
        let mut b=BIG::new();
        let mut c=BIG::new();
    
        u.inc(BIG::invmod256(self.lastbits(8)));
    
        let mut i=8;
        while i<BIGBITS {
            u.norm();
            b.copy(self);
            b.mod2m(i);
            let mut t1=BIG::smul(&u,&b);
            t1.shr(i);
            c.copy(self);
            c.shr(i);
            c.mod2m(i);
    
            let mut t2=BIG::smul(&u,&c);
            t2.mod2m(i);
            t1.add(&t2); t1.norm();
            b=BIG::smul(&t1,&u);
            t1.copy(&b);
            t1.mod2m(i);
    
            t2.one(); t2.shl(i); t1.rsub(&t2); t1.norm();
            t1.shl(i);
            u.add(&t1);
            i<<=1;
        }
        u.mod2m(BIGBITS);
        self.copy(&u);
        self.norm();
    }

/* reduce self mod m */
    pub fn rmod(&mut self,n: &BIG) {
        let mut k=0;
        let mut m=BIG::new_copy(n);
	    let mut r=BIG::new();
        self.norm();
        if BIG::comp(self,&m)<0 {return}
        loop {
            m.fshl(1);
            k += 1;
            if BIG::comp(self,&m)<0 {break}
        }
    
        while k>0 {
            m.fshr(1);

		r.copy(self);
		r.sub(&m);
		r.norm();
		self.cmove(&r,(1-((r.w[NLEN-1]>>(arch::CHUNK-1))&1)) as isize);
/*
            if BIG::comp(self,&m)>=0 {
				self.sub(&m);
				self.norm();
            } */
            k -= 1;
        }
    }

/* divide self by m */
    pub fn div(&mut self,n: &BIG) {
        let mut k=0;
        self.norm();
        let mut e=BIG::new_int(1);
        let mut b=BIG::new_copy(self);
        let mut m=BIG::new_copy(n);
        let mut r=BIG::new();
        self.zero();
    
        while BIG::comp(&b,&m)>=0 {
            e.fshl(1);
            m.fshl(1);
            k += 1;
        }
    
        while k>0 {
            m.fshr(1);
            e.fshr(1);

		r.copy(&b);
		r.sub(&m);
		r.norm();
		let d=(1-((r.w[NLEN-1]>>(arch::CHUNK-1))&1)) as isize;
		b.cmove(&r,d);
		r.copy(self);
		r.add(&e);
		r.norm();
		self.cmove(&r,d);
/*
            if BIG::comp(&b,&m)>=0 {
				self.add(&e);
				self.norm();
				b.sub(&m);
				b.norm();
            } */
            k -= 1;
        }
    }

/* get 8*MODBYTES size random number */
    pub fn random(rng: &mut RAND) -> BIG {
        let mut m=BIG::new();
        let mut j=0;
        let mut r:u8=0;
/* generate random BIG */ 
        for _ in 0..8*(MODBYTES as usize)  {
            if j==0 {
                r=rng.getbyte()
            } else {r>>=1}

            let b= (r as Chunk)&1; 
            m.shl(1); m.w[0]+=b;// m.inc(b)
            j+=1; j&=7; 
        }
        return m;
    }

/* Create random BIG in portable way, one bit at a time */
    pub fn randomnum(q: &BIG,rng: &mut RAND) -> BIG {
        let mut d=DBIG::new();
        let mut j=0;
        let mut r:u8=0;
        let t=BIG::new_copy(q);
        for _ in 0..2*t.nbits() {
            if j==0 {
                r=rng.getbyte();
            } else {r>>=1}

            let b= (r as Chunk)&1;
            d.shl(1); d.w[0]+=b; // m.inc(b);
            j+=1; j&=7; 
        }
        let m=d.dmod(q);
        return m;
    }


   /* Jacobi Symbol (this/p). Returns 0, 1 or -1 */
    pub fn jacobi(&mut self,p: &BIG) -> isize {
        let mut m:usize=0;
        let mut t=BIG::new();
        let mut x=BIG::new();
        let mut n=BIG::new();
        let zilch=BIG::new();
        let one=BIG::new_int(1);
        if p.parity()==0 || BIG::comp(self,&zilch)==0 || BIG::comp(p,&one)<=0 {return 0}
        self.norm();

        x.copy(self);
        n.copy(p);
        x.rmod(p);

        while BIG::comp(&n,&one)>0 {
            if BIG::comp(&x,&zilch)==0 {return 0}
            let n8=n.lastbits(3) as usize;
            let mut k=0;
            while x.parity()==0 {
				k += 1;
				x.shr(1);
            }
            if k%2==1 {m+=(n8*n8-1)/8}
            m+=(n8-1)*((x.lastbits(2) as usize)-1)/4;
            t.copy(&n);
            t.rmod(&x);
            n.copy(&x);
            x.copy(&t);
            m%=2;
    
        }
        if m==0 {return 1}
        else {return -1}
    }

/* self=1/self mod p. Binary method */
    pub fn invmodp(&mut self,p: &BIG) {
        self.rmod(p);
        let mut u=BIG::new_copy(self);
        let mut v=BIG::new_copy(p);
        let mut x1=BIG::new_int(1);
        let mut x2=BIG::new();
        let mut t=BIG::new();
        let one=BIG::new_int(1);
    
        while (BIG::comp(&u,&one) != 0 ) && (BIG::comp(&v,&one) != 0 ) {
            while u.parity()==0 {
				u.fshr(1);
				if x1.parity() != 0 {
                    x1.add(p);
                    x1.norm();
				}
				x1.fshr(1);
            }
            while v.parity()==0 {
				v.fshr(1);
				if x2.parity() != 0  {
                    x2.add(p);
                    x2.norm();
				}
				x2.fshr(1);
            }
            if BIG::comp(&u,&v)>=0 {
				u.sub(&v);
				u.norm();
                if BIG::comp(&x1,&x2)>=0 {x1.sub(&x2)}
				else
				{
                    t.copy(p);
                    t.sub(&x2);
                    x1.add(&t);
				}
				x1.norm();
            }
            else
            {
				v.sub(&u);
				v.norm();
                if BIG::comp(&x2,&x1)>=0 {x2.sub(&x1)}
				else
				{
                    t.copy(p);
                    t.sub(&x1);
                    x2.add(&t);
				}
				x2.norm();
            }
        }
        if BIG::comp(&u,&one)==0 {self.copy(&x1)}
        else {self.copy(&x2)}
    }
/*
    pub fn isok(&self) ->bool {
        let mut ok=true;
        for i in 0 ..NLEN {
            if (self.w[i]>>BASEBITS)!=0 {ok=false;}
        }
        return ok;
    }
*/
   /* return a*b as DBIG */
//#[cfg(D32)]
    pub fn mul(a: &BIG,b: &BIG) -> DBIG {
        let mut c=DBIG::new();
        let rm=BMASK as DChunk;
        let rb=BASEBITS;
     //if !a.isok() {println!("a not normalised in mul");}
     //if !b.isok() {println!("b not normalised in mul");}

        let mut d: [DChunk; DNLEN] = [0; DNLEN];
        for i in 0 ..NLEN {
            d[i]=(a.w[i] as DChunk)*(b.w[i] as DChunk);
        }
        let mut s=d[0];
        let mut t=s; c.w[0]=(t&rm) as Chunk; 
        let mut co=t>>rb;
        for k in 1 ..NLEN {
            s+=d[k]; t=co+s;
            for i in 1+k/2..k+1
                {t+=((a.w[i]-a.w[k-i]) as DChunk)*((b.w[k-i]-b.w[i]) as DChunk)}
            c.w[k]=(t&rm) as Chunk; co=t>>rb;
        }
        for k in NLEN ..2*NLEN-1 {
            s-=d[k-NLEN]; t=co+s;
            let mut i=1+k/2;
            while i<NLEN {
                t+=((a.w[i]-a.w[k-i]) as DChunk)*((b.w[k-i]-b.w[i]) as DChunk);
                i+=1;
            }
        
            c.w[k]=(t&rm) as Chunk; co=t>>rb;
        }
        c.w[2*NLEN-1]=co as Chunk;
        return c;
    }

/* return a^2 as DBIG */
//#[cfg(D32)]  
    pub fn sqr(a: &BIG) -> DBIG {
        let mut c=DBIG::new();
        let rm=BMASK as DChunk;
        let rb=BASEBITS;
 
        //if !a.isok() {println!("a not normalised in sqr");}

        let mut t=(a.w[0] as DChunk)*(a.w[0] as DChunk); 
        c.w[0]=(t&rm) as Chunk; let mut co=t>>rb;

        let mut j=1;
        while j<NLEN-1
        {
            t=(a.w[j] as DChunk)*(a.w[0] as DChunk); for  i in 1..(j+1)/2 {t+=(a.w[j-i] as DChunk)*(a.w[i] as DChunk);} t+=t;  t+=co; 
            c.w[j]=(t&rm) as Chunk; co=t>>rb;
            j+=1;
            t=(a.w[j] as DChunk)*(a.w[0] as DChunk); for  i in 1..(j+1)/2 {t+=(a.w[j-i] as DChunk)*(a.w[i] as DChunk);} t+=t; t+=co; t+=(a.w[j/2] as DChunk)*(a.w[j/2] as DChunk); 
            c.w[j]=(t&rm) as Chunk; co=t>>rb;
            j+=1;
        }

        j=NLEN+(NLEN%2)-1;
        while j<DNLEN-3
        {
            t=(a.w[NLEN-1] as DChunk)*(a.w[j+1-NLEN] as DChunk); for i in j+2-NLEN ..(j+1)/2 {t+=(a.w[j-i] as DChunk)*(a.w[i] as DChunk);} t+=t; t+=co; 
            c.w[j]=(t&rm) as Chunk; co=t>>rb;
            j+=1;
            t=(a.w[NLEN-1] as DChunk)*(a.w[j+1-NLEN] as DChunk); for i in j+2-NLEN ..(j+1)/2 {t+=(a.w[j-i] as DChunk)*(a.w[i] as DChunk);} t+=t; t+=co; t+=(a.w[j/2] as DChunk)*(a.w[j/2] as DChunk); 
            c.w[j]=(t&rm) as Chunk; co=t>>rb;
            j+=1;
        }

        t=(a.w[NLEN-2] as DChunk)*(a.w[NLEN-1] as DChunk);
        t+=t; t+=co;
        c.w[DNLEN-3]=(t&rm) as Chunk; co=t>>rb;
    
        t=(a.w[NLEN-1] as DChunk)*(a.w[NLEN-1] as DChunk)+co; 
        c.w[DNLEN-2]=(t&rm) as Chunk; co=t>>rb;
        c.w[DNLEN-1]=co as Chunk;

        return c;
    }


//#[cfg(D32)]
    pub fn monty(md: &BIG,mc: Chunk,d: &mut DBIG) -> BIG {
        let mut b=BIG::new();           
        let rm=BMASK as DChunk;
        let rb=BASEBITS;

        let mut dd: [DChunk; NLEN] = [0; NLEN];
        let mut v: [Chunk; NLEN] = [0; NLEN];
            
        b.zero();
            
        let mut t=d.w[0] as DChunk; v[0]=(((t&rm) as Chunk).wrapping_mul(mc))&BMASK; 
        t+=(v[0] as DChunk)*(md.w[0] as DChunk); let mut c=(d.w[1] as DChunk)+(t>>rb); let mut s:DChunk=0;
        for k in 1 ..NLEN {
            t=c+s+(v[0] as DChunk)*(md.w[k] as DChunk);
            let mut i=1+k/2;
            while i<k {
                t+=((v[k-i]-v[i]) as DChunk)*((md.w[i]-md.w[k-i]) as DChunk);
                i+=1;
            }
            v[k]=(((t&rm) as Chunk).wrapping_mul(mc))&BMASK; 
            t+=(v[k] as DChunk)*(md.w[0] as DChunk); c=(d.w[k+1] as DChunk)+(t>>rb);
            dd[k]=(v[k] as DChunk)*(md.w[k] as DChunk); s+=dd[k];
        }
            
        for k in NLEN ..2*NLEN-1
        {
            t=c+s;
            let mut i=1+k/2;
            while i<NLEN {
                t+=((v[k-i]-v[i]) as DChunk)*((md.w[i]-md.w[k-i]) as DChunk);
                i+=1;
            }
            b.w[k-NLEN]=(t&rm) as Chunk; c=(d.w[k+1] as DChunk)+(t>>rb); s-=dd[k+1-NLEN];
        }
        b.w[NLEN-1]=(c&rm) as Chunk;  
   //     b.norm();
        return b;
    }
    


/* return a*b as DBIG 
#[cfg(D64)]
    pub fn mul(a: &BIG,b: &BIG) -> DBIG {
        let mut c=DBIG::new();
        //let mut carry = 0 as Chunk;
        let mut carry:Chunk;
        for i in 0 ..NLEN {
            carry=0;
            for j in 0 ..NLEN {
                let tuple=BIG::muladd(a.w[i],b.w[j],carry,c.w[i+j]);
                carry=tuple.0; c.w[i+j]=tuple.1;
            }
            c.w[NLEN+i]=carry;
        }
        return c;
    } 

// return a^2 as DBIG 
#[cfg(D64)]
    pub fn sqr(a: &BIG) -> DBIG {
        let mut c=DBIG::new();
        //let mut carry = 0 as Chunk;
        let mut carry:Chunk;
        for i in 0 ..NLEN {
            carry=0;
            for j in i+1 ..NLEN {
                let tuple=BIG::muladd(2*a.w[i],a.w[j],carry,c.w[i+j]);
                carry=tuple.0; c.w[i+j]=tuple.1;
            //carry,c.w[i+j]=muladd(2*a.w[i],a.w[j],carry,c.w[i+j])
            //carry=c.muladd(2*a.w[i],a.w[j],carry,i+j)
            }
            c.w[NLEN+i]=carry;
        }

        for i in 0 ..NLEN {
            let tuple=BIG::muladd(a.w[i],a.w[i],0,c.w[2*i]);
            c.w[2*i]=tuple.1;
            c.w[2*i+1]+=tuple.0;
        //c.w[2*i+1]+=c.muladd(a.w[i],a.w[i],0,2*i)
        }
        c.norm();
        return c;
    } 

#[cfg(D64)]
    pub fn monty(md: &BIG,mc: Chunk,d: &mut DBIG) -> BIG {
        let mut b=BIG::new();     
        //let mut carry=0 as Chunk; 
        let mut carry:Chunk;
        //let mut m=0 as Chunk;
        let mut m:Chunk;
        for i in 0 ..NLEN {
            if mc==-1 { 
                m=(-d.w[i])&BMASK;
            } else {
                if mc==1 {
                    m=d.w[i];
                } else {
                    m=(mc*d.w[i])&BMASK;
                }
            }

            carry=0;
            for j in 0 ..NLEN {
                let tuple=BIG::muladd(m,md.w[j],carry,d.w[i+j]);
                carry=tuple.0; d.w[i+j]=tuple.1;
            }
            d.w[NLEN+i]+=carry;
        }

        for i in 0 ..NLEN {
            b.w[i]=d.w[NLEN+i];
        } 
        b.norm();
        return b;  
    }

*/


    /* return a*b mod m */
    pub fn modmul(a: &mut BIG,b: &mut BIG,m: &BIG) -> BIG {
        a.rmod(m);
        b.rmod(m);
        let mut d=BIG::mul(a,b);
        return d.dmod(m);
    }
    
    /* return a^2 mod m */
    pub fn modsqr(a: &mut BIG,m: &BIG) -> BIG {
        a.rmod(m);
        let mut d=BIG::sqr(a);
        return d.dmod(m);
    }
    
    /* return -a mod m */
    pub fn modneg(a: &mut BIG,m: &BIG) -> BIG {
        a.rmod(m);
        return m.minus(a);
    }

    /* return this^e mod m */
    pub fn powmod(&mut self,e: &mut BIG,m: &BIG) -> BIG {
        self.norm();
        e.norm();
        let mut a=BIG::new_int(1);
        let mut z=BIG::new_copy(e);
        let mut s=BIG::new_copy(self);
        loop {      
            let bt=z.parity();       
            z.fshr(1);    
            if bt==1 {a=BIG::modmul(&mut a,&mut s,m)}
            if z.iszilch() {break}
            s=BIG::modsqr(&mut s,m);         
        }
        return a;
    }

}
 
/*
fn main() {
	let fd: [i32; NLEN as usize] = [1, 2, 3, 4, 5, 6, 7, 8, 9];	
	let mut x= BIG::new();
	x.inc(3);
 	println!("{}", x.w[0]);	
 	let mut y= BIG::new_int(7);
 	println!("{}", y.w[0]);	
 	y=BIG::new_copy(&x);
	println!("{}", y.w[0]); 	
	x.add(&y);
	x.add(&y);
	println!("{}", x.w[0]); 	
	let mut z= BIG::new_ints(&fd);
	println!("{}", z.w[0]); 	
	z.shr(3);
	z.norm();
	println!("{:X}", z.w[0]); 	

	println!("{}",z.tostring());

    let mut a = BIG::new_int(3);
    let mut m = BIG::new_ints(&MODULUS);

    println!("rom::MODULUS= {}",m.tostring());

    let mut e = BIG::new_copy(&m);
    e.dec(1); e.norm();
    println!("Exponent= {}",e.tostring());
//    for i in 0..20
//    {
        a=a.powmod(&mut e,&mut m);
//        a.inc(2);
//    }
    println!("Result= {}",a.tostring());

}
*/
