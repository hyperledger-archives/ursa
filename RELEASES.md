# How Ursa Releases

Releases are made after enough features and improvements have been made as decided by the Ursa working group.
When a release is going to be done the following process is followed:

- An RC branch is forked from `master` with the name `rcvx.x.x`
- Additional tests are made that are not covered by the CI pipeline line external audits or penetration tests.
- When enough testing has been applied, the RC branch is merged with master
- master is tagged with the release number `vx.x.x`
- A rust crate is published with this version number

If fixes are needed from previous versions, branches would be made so work can be done directly at that point. For example, if 2.0 and 1.0 have been released by a security fix is needed in 1.0, a 1.0 branch will be made and the newer version would be 1.0.1.
