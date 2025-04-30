# remove git repo
rm -rf .git

# To remove tracked files that are now in .gitignore, do this:
git rm -r --cached .
git add .
git commit -m "Remove ignored files from repo"