all: prepare fuse_auth

fuse_auth:
	mkdir -p mnt
	mount_afpfs afp://test_usr:test_pwd@localhost/afpfs_test `pwd`/mnt
	echo 'You should read this back' >mnt/sample.txt
	grep -E '^You should read this back$$' `pwd`/mnt/sample.txt >/dev/null
	afp_client unmount `pwd`/mnt
	mount_afpfs afp://localhost/afpfs_test `pwd`/mnt
	ls -al mnt/ | grep sample.txt >/dev/null
	grep -E '^You should read this back$$' `pwd`/mnt/sample.txt >/dev/null
	afp_client unmount `pwd`/mnt
	mount_afpfs afp://test_usr:test_pwd@localhost/afpfs_test `pwd`/mnt
	grep -E '^You should read this back$$' `pwd`/mnt/sample.txt >/dev/null
	wc -l mnt/sample.txt | grep 1 >/dev/null
	rm `pwd`/mnt/sample.txt
	afp_client unmount `pwd`/mnt
	@echo 'fuse_auth test passed.'

prepare:
	afp_client unmount `pwd`/mnt >/dev/null 2>&1 || true
	afp_client exit >/dev/null 2>&1 || true
