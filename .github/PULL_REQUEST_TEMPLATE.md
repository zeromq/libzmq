# Pull Request Notice

Before sending a pull request make sure each commit solves one clear, minimal,
plausible problem. Further each commit should have the following format:

```
Problem: X is broken

Solution: do Y and Z to fix X
```

Please try to have the code changes conform to our coding style. For your
convenience, you can install clang-format (at least version 5.0) and then
run ```make clang-format-check```. Don't fix existing issues, if any - just
make sure your changes are compliant. ```make clang-format-diff``` will
automatically apply the required changes.
To set a specific clang-format binary with autotools, you can for example
run: ```./configure CLANG_FORMAT=clang-format-5.0```

Please avoid sending a pull request with recursive merge nodes, as they
are impossible to fix once merged. Please rebase your branch on
zeromq/libzmq master instead of merging it.

```
git remote add upstream git@github.com:zeromq/libzmq.git
git fetch upstream
git rebase upstream/master
git push -f
```

In case you already merged instead of rebasing you can drop the merge commit.

```
git rebase -i HEAD~10
```

Now, find your merge commit and mark it as drop and save. Finally rebase!

If you are a new contributor please have a look at our contributing guidelines:
[CONTRIBUTING](http://zeromq.org/docs:contributing)

# FIRST TIME CONTRIBUTORS PLEASE NOTE

Please add an additional commit with a relicensing grant.

[Example](https://github.com/zeromq/libzmq/commit/fecbd42dbe45455fff3b6456350ceca047b82050)

[More information on RELICENSING effort](https://github.com/zeromq/libzmq/tree/master/RELICENSE/README.md)
