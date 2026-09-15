# ChatGPT workflow notes

Read [AGENTS.md](AGENTS.md) first, then its linked docs
([`docs/SOURCES.md`](docs/SOURCES.md), [`docs/ROADMAP.md`](docs/ROADMAP.md)).
This file only records ChatGPT-specific workflow lessons for Work Chats so future Work Chats do not
have to rediscover them.

## GitHub handling

When the user selects the GitHub plugin or asks you to work on this repository,
use the GitHub connector for publishing branches, file updates, and pull
requests. You can still use the local clone for reading, editing, testing, and
building commits, but do not spend time repeatedly trying unauthenticated shell
pushes if `git push` fails with a credential prompt or "could not read
Username".

Preferred flow for a new PR:

1. Make and test changes locally.
2. Commit locally so the intended tree is easy to inspect.
3. Create the remote branch with the GitHub connector from the exact base SHA
   used locally, for example `git rev-parse origin/main`.
4. Upload changed files with the contents API tools:
   - Use `github_update_file` for existing files.
   - Use `github_create_file` for new files.
   - For `github_update_file`, get the current blob SHA from the target branch
     with the connector contents endpoint, or from local git if that tree is
     available.
5. Open the PR with `github_create_pull_request`.
6. Verify the remote branch with `github_compare_commits` before telling the
   user the PR is ready.

Preferred flow for adding to an existing PR:

1. Fetch or inspect the PR and note its head branch.
2. Add or update files on that head branch with `github_create_file` or
   `github_update_file`.
3. Check each connector response for `isError`; some connector failures may
   return an error payload instead of throwing.
4. Re-run `github_compare_commits` against the PR base and head branch and make
   sure the expected files are present.

Avoid the low-level blob/tree/commit route unless the connector returns the SHAs
you need at every step. In this repo, the contents API route has been the least
surprising path.

For PR #38 (`build/parser-coverage-v3`), the remote branch was published through
the connector because the shell could not authenticate to GitHub. One file
appeared to upload but was absent from the compare until the response was
checked and the file was replayed. Always trust the final compare, not a loop
that merely completed.
