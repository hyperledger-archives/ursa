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

use goldilocks::big::NLEN;
use arch::Chunk;

// Base Bits= 58
// Goldilocks modulus
pub const MODULUS:[Chunk;NLEN]=[0x3FFFFFFFFFFFFFF,0x3FFFFFFFFFFFFFF,0x3FFFFFFFFFFFFFF,0x3FBFFFFFFFFFFFF,0x3FFFFFFFFFFFFFF,0x3FFFFFFFFFFFFFF,0x3FFFFFFFFFFFFFF,0x3FFFFFFFFFF];
pub const R2MODP:[Chunk;NLEN]=[0x200000000,0x0,0x0,0x0,0x3000000,0x0,0x0,0x0];
pub const MCONST:Chunk=0x1;

// Goldilocks curve
pub const CURVE_COF_I:isize = 4;
pub const CURVE_A:isize = 1;
pub const CURVE_B_I:isize = -39081;
pub const CURVE_COF:[Chunk;NLEN]=[0x4,0x0,0x0,0x0,0x0,0x0,0x0,0x0];
pub const CURVE_B:[Chunk;NLEN]=[0x3FFFFFFFFFF6756,0x3FFFFFFFFFFFFFF,0x3FFFFFFFFFFFFFF,0x3FBFFFFFFFFFFFF,0x3FFFFFFFFFFFFFF,0x3FFFFFFFFFFFFFF,0x3FFFFFFFFFFFFFF,0x3FFFFFFFFFF];
pub const CURVE_ORDER:[Chunk;NLEN]=[0x378C292AB5844F3,0x3309CA37163D548,0x1B49AED63690216,0x3FDF3288FA7113B,0x3FFFFFFFFFFFFFF,0x3FFFFFFFFFFFFFF,0x3FFFFFFFFFFFFFF,0xFFFFFFFFFF];
pub const CURVE_GX:[Chunk;NLEN]=[0x155555555555555,0x155555555555555,0x155555555555555,0x2A5555555555555,0x2AAAAAAAAAAAAAA,0x2AAAAAAAAAAAAAA,0x2AAAAAAAAAAAAAA,0x2AAAAAAAAAA];
pub const CURVE_GY:[Chunk;NLEN]=[0x2EAFBCDEA9386ED,0x32CAFB473681AF6,0x25833A2A3098BBB,0x1CA2B6312E03595,0x35884DD7B7E36D,0x21B0AC00DBB5E8,0x17048DB359D6205,0x2B817A58D2B];

