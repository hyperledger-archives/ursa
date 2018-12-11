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


pub const HASH224: usize=28;
pub const HASH256: usize=32;
pub const HASH384: usize=48;
pub const HASH512: usize=64;
pub const SHAKE128: usize=16;
pub const SHAKE256: usize=32;

const ROUNDS: usize=24;

const RC : [u64;24] = [
		0x0000000000000001,0x0000000000008082,0x800000000000808A,0x8000000080008000,
		0x000000000000808B,0x0000000080000001,0x8000000080008081,0x8000000000008009,
		0x000000000000008A,0x0000000000000088,0x0000000080008009,0x000000008000000A,
		0x000000008000808B,0x800000000000008B,0x8000000000008089,0x8000000000008003,
		0x8000000000008002,0x8000000000000080,0x000000000000800A,0x800000008000000A,
		0x8000000080008081,0x8000000000008080,0x0000000080000001,0x8000000080008008];



pub struct SHA3 {
	length: u64,
	rate: usize,
	len: usize, 
	s: [[u64;5];5]
}

impl SHA3 {
	fn rotl(x: u64,n: u64) -> u64 {
		return ((x)<<n) | ((x)>>(64-n));
	}

	fn transform(&mut self) { /* basic transformation step */
		let mut c: [u64; 5] = [0; 5];
		let mut d: [u64; 5] = [0; 5];
		let mut b: [[u64;5];5]=[[0;5];5];

		for k in 0..ROUNDS  {
			c[0]=self.s[0][0]^self.s[0][1]^self.s[0][2]^self.s[0][3]^self.s[0][4];
			c[1]=self.s[1][0]^self.s[1][1]^self.s[1][2]^self.s[1][3]^self.s[1][4];
			c[2]=self.s[2][0]^self.s[2][1]^self.s[2][2]^self.s[2][3]^self.s[2][4];
			c[3]=self.s[3][0]^self.s[3][1]^self.s[3][2]^self.s[3][3]^self.s[3][4];
			c[4]=self.s[4][0]^self.s[4][1]^self.s[4][2]^self.s[4][3]^self.s[4][4];

			d[0]=c[4]^SHA3::rotl(c[1],1);
			d[1]=c[0]^SHA3::rotl(c[2],1);
			d[2]=c[1]^SHA3::rotl(c[3],1);
			d[3]=c[2]^SHA3::rotl(c[4],1);
			d[4]=c[3]^SHA3::rotl(c[0],1);

			for i in 0..5 {
				for j in 0..5 {
					self.s[i][j]^=d[i];
				}
			}

			b[0][0]=self.s[0][0];
			b[1][3]=SHA3::rotl(self.s[0][1],36);
			b[2][1]=SHA3::rotl(self.s[0][2],3);
			b[3][4]=SHA3::rotl(self.s[0][3],41);
			b[4][2]=SHA3::rotl(self.s[0][4],18);

			b[0][2]=SHA3::rotl(self.s[1][0],1);
			b[1][0]=SHA3::rotl(self.s[1][1],44);
			b[2][3]=SHA3::rotl(self.s[1][2],10);
			b[3][1]=SHA3::rotl(self.s[1][3],45);
			b[4][4]=SHA3::rotl(self.s[1][4],2);

			b[0][4]=SHA3::rotl(self.s[2][0],62);
			b[1][2]=SHA3::rotl(self.s[2][1],6);
			b[2][0]=SHA3::rotl(self.s[2][2],43);
			b[3][3]=SHA3::rotl(self.s[2][3],15);
			b[4][1]=SHA3::rotl(self.s[2][4],61);

			b[0][1]=SHA3::rotl(self.s[3][0],28);
			b[1][4]=SHA3::rotl(self.s[3][1],55);
			b[2][2]=SHA3::rotl(self.s[3][2],25);
			b[3][0]=SHA3::rotl(self.s[3][3],21);
			b[4][3]=SHA3::rotl(self.s[3][4],56);

			b[0][3]=SHA3::rotl(self.s[4][0],27);
			b[1][1]=SHA3::rotl(self.s[4][1],20);
			b[2][4]=SHA3::rotl(self.s[4][2],39);
			b[3][2]=SHA3::rotl(self.s[4][3],8);
			b[4][0]=SHA3::rotl(self.s[4][4],14);

			for i in 0..5 {
				for j in 0..5 {
					self.s[i][j]=b[i][j]^(!b[(i+1)%5][j]&b[(i+2)%5][j]);
				}
			}

			self.s[0][0]^=RC[k];
		}
	} 	

/* Initialise Hash function */
	pub fn init(&mut self,olen: usize) { /* initialise */
		for i in 0..5 {
			for j in 0..5 {
				self.s[i][j]=0;
			}
		}
		self.length=0; 
		self.len=olen;
		self.rate=200-2*olen;
	}	

	pub fn new(olen: usize) -> SHA3 {
		let mut nh=SHA3 {
			length: 0,
			rate: 0,
			len: 0,
			s: [[0;5];5]
		};
		nh.init(olen);
		return nh;
	}

/* process a single byte */
	pub fn process(&mut self,byt: u8) { /* process the next message byte */
		let cnt=(self.length%(self.rate as u64)) as usize;
		let b=cnt%8;
		let ind=cnt/8;
		let i=ind%5;
		let j=ind/5;
		self.s[i][j]^=((byt&0xff) as u64) << (8*b);
		self.length+=1;
		if cnt+1 == self.rate {
			self.transform();
		}
	}

	pub fn squeeze(&mut self,buff: &mut [u8],olen: usize) {
		//let olen=buff.len();
		let mut done=false;
		let mut m=0;
		loop {
			for j in 0..5 {
				for i in 0..5 {
					let mut el=self.s[i][j];
					for _ in 0..8 {
						buff[m]=(el&0xff) as u8;
						m+=1;
						if m>=olen || (m%self.rate)==0 {
							done=true;
							break;
						}
						el>>=8;
					}
					if done {break}
				}
				if done {break}
			}
			if m>=olen {break}
			done=false;
			self.transform();			
		} 

	}

/* Generate 32-byte Hash */
	pub fn hash(&mut self,digest: &mut [u8]) { /* pad message and finish - supply digest */
		let q=self.rate-(self.length%(self.rate as u64)) as usize;
		if q==1 {
			self.process(0x86);
		} else {
			self.process(0x06);
			while (self.length%(self.rate as u64)) as usize != self.rate-1 {self.process(0x00)}
			self.process(0x80);
		}
		let hlen=self.len as usize;
		self.squeeze(digest,hlen);
	}

	pub fn shake(&mut self,digest: &mut[u8],olen: usize) {
		let q=self.rate-(self.length%(self.rate as u64)) as usize;
		if q==1 {
			self.process(0x9f);
		} else {
			self.process(0x1f);
			while (self.length%(self.rate as u64)) as usize != self.rate-1 {self.process(0x00)}
			self.process(0x80);
		}
		self.squeeze(digest,olen);		
	}

}

//916f6061fe879741ca6469b43971dfdb28b1a32dc36cb3254e812be27aad1d18
//afebb2ef542e6579c50cad06d2e578f9f8dd6881d7dc824d26360feebf18a4fa73e3261122948efcfd492e74e82e2189ed0fb440d187f382270cb455f21dd185
//98be04516c04cc73593fef3ed0352ea9f6443942d6950e29a372a681c3deaf4535423709b02843948684e029010badcc0acd8303fc85fdad3eabf4f78cae165635f57afd28810fc2
/*
fn main() {
	let s = String::from("abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu");	
	let mut digest: [u8;100]=[0;100];	
	let test = s.into_bytes();

	let mut sh=SHA3::new(HASH256);
	for i in 0..test.len(){
		sh.process(test[i]);
	}
	sh.hash(&mut digest);    
	for i in 0..32 {print!("{:02x}",digest[i])}
	println!("");

	sh=SHA3::new(HASH512);
	for i in 0..test.len(){
		sh.process(test[i]);
	}
	sh.hash(&mut digest);    
	for i in 0..64 {print!("{:02x}",digest[i])}
	println!("");

	sh=SHA3::new(SHAKE256);
	for i in 0..test.len(){
		sh.process(test[i]);
	}
	sh.shake(&mut digest,72);    
	for i in 0..72 {print!("{:02x}",digest[i])}
	println!("");

} */
