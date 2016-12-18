# Pull Request Notice

Before sending a pull request make sure each commit solves one clear, minimal,
plausible problem. Further each commit should have the following format:

```
Problem: X is broken

Solution: do Y and Z to fix X
```

Please avoid sending a pull request with recursive merge nodes, as they
are impossible to fix once merged. Please rebase your branch on
zeromq/libzmq master instead of merging it.

git remote add upstream git@github.com:zeromq/libzmq.git
git fetch upstream
git rebase upstream/master
git push -f

In case you already merged instead of rebasing you can drop the merge commit.

git rebase -i HEAD~10

Now, find your merge commit and mark it as drop and save. Finally rebase!

If you are a new contributor please have a look at our contributing guidelines:
[CONTRIBUTING](http://zeromq.org/docs:contributing)
