Releasing software
-------------------

When releasing a new version, the following steps should be taken:

1. Make sure all automated tests pass.

2. Make sure the package metadata in ``setup.py`` is up-to-date. You can
   verify the information by re-generating the egg info::

    python setup.py egg_info

   and inspecting ``src/SATOSA.egg-info/PKG-INFO``. You should also make sure
   that the long description renders as valid reStructuredText. You can
   do this by using the ``rst2html.py`` utility from docutils_::

    python setup.py --long-description | rst2html > test.html

   If this will produce warning or errors, PyPI will be unable to render
   the long description nicely. It will treat it as plain text instead.

3. Update the version in the .bumpversion.cfg_ and setup.py_ files
   and report the changes in CHANGELOG.md_. Commit the changes.::

    git add CHANGELOG.md
    git add setup.py
    git add .bumpversion.cfg
    git commit -v -s -m "Release version X.Y.Z"

4. Create a release branch_::

    git branch vX.Y.Z

5. Create a release tag_::

    git tag -a -s vX.Y.Z -m "Version X.Y.Z"

6. Push these changes to Github::

    git push --follow-tags origin vX.Y.Z
    git push --follow-tags origin vX.Y.Z:vX.Y.Z


From there, travis will run the tests and, on success, it will create a docker
image with the tag as the image-tag, as well as it will create and upload a new
PyPI package.


.. _docutils: http://docutils.sourceforge.net/
.. _.bumpversion.cfg: https://github.com/IdentityPython/SATOSA/blob/master/.bumpversion.cfg
.. _CHANGELOG.md: https://github.com/IdentityPython/SATOSA/blob/master/CHANGELOG.md
.. _branch: https://git-scm.com/book/en/v2/Git-Branching-Branches-in-a-Nutshell
.. _tag: https://git-scm.com/book/en/v2/Git-Basics-Tagging#_annotated_tags
