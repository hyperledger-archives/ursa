------------
Contributing
------------

==========================================
Ways to Contribute to Hyperledger Ursa
==========================================

Contributions from the development community help improve the capabilities of
Hyperledger Ursa. These contributions are the most effective way to
make a positive impact on the project.

Ways you can contribute:

* Bugs or issues: Report problems or defects found when working with Ursa
* Core features and enhancements: Provide expanded capabilities or optimizations
* Documentation: Improve existing documentation or create new information
* Tests: Add functional, performance, or scalability tests

Hyperledger Ursa issues can be found in :ref:`jira`.  Any unassigned items
are probably still open. When in doubt, ask on RocketChat about
a specific JIRA issue (see :doc:`join_the_discussion`).

==================
The Commit Process
==================

Hyperledger Ursa is Apache 2.0 licensed and accepts contributions
via `GitHub <https://github.com/hyperledger/ursa>`_
pull requests. When contributing code, please follow these guidelines:

* Fork the repository and make your changes in a feature branch
* Include unit and integration tests for any new features and updates
  to existing tests
* Ensure that the unit and integration tests run successfully.

**Pull Request Guidelines**

A pull request can contain a single commit or multiple commits. The most
important guideline is that a single commit should map to a single fix or
enhancement. Here are some example scenarios:

* If a pull request adds a feature but also fixes two bugs, the pull
  request should have three commits: one commit for the feature change and
  two commits for the bug fixes.
* If a PR is opened with five commits that contain changes to fix a single
  issue, the PR should be rebased to a single commit.
* If a PR is opened with several commits, where the first commit fixes one issue
  and the rest fix a separate issue, the PR should be rebased to two
  commits (one for each issue).

**Important:**
  Your pull request should be rebased against the current master branch. Do
  not merge the current master branch in with your topic branch. Do not use the
  Update Branch button provided by GitHub on the pull request page.

**Commit Messages**

Commit messages should follow common Git conventions, such as using the
imperative mood, separate subject lines, and a line length of 72 characters.
These rules are well documented in `Chris Beam's blog post
<https://chris.beams.io/posts/git-commit/#seven-rules>`_.

**Signed-off-by**

Each commit must include a "Signed-off-by" line in the commit message
(``git commit -s``). This sign-off indicates that you agree the commit satisfies
the `Developer Certificate of Origin (DCO) <http://developercertificate.org/>`_.

**Commit Email Address**

Your commit email address must match your GitHub email address. For more
information, see
https://help.github.com/articles/setting-your-commit-email-address-in-git/

**Important GitHub Requirements**

A pull request cannot merged until it has passed these status checks:

* The build must pass on Jenkins
* The PR must be approved by at least two maintainers without any
  outstanding requests for changes
* Any non-black-box use of an algorithm must include a theoretical maintainer
  as one of the two reviewers.

**Integrating GitHub Commits with JIRA**

You can link JIRA issues to your commits, which  will integrate
developer activity with the associated issue. JIRA uses the issue key to
associate the commit with the issue, so that the commit can be summarized in the
development panel for the JIRA issue.

When you make a commit, add the JIRA issue key to the end of the commit message
or to the branch name. Either method should integrate your commit with the JIRA
issue that it references.

.. Licensed under Creative Commons Attribution 4.0 International License
.. https://creativecommons.org/licenses/by/4.0/
