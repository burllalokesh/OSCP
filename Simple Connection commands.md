##ssh
```
ssh -p 22 user@10.10.10.10
```
##connection with id_rsa
```
vim id_rsa
chmod 600 id_rsa
ssh -p user@10.10.10.10 -i id_rsa
```
##write access to a users/.ssh/

we can place our public key in the user's ssh directory at /home/user/.ssh/authorized_keys. This technique is usually used to gain ssh access after gaining a shell as that user. The current SSH configuration will not accept keys written by other users, so it will only work if we have already gained control over that user. We must first create a new key with ssh-keygen and the -f flag to specify the output file:
```
ssh-keygen -f key
```
This will give us two files: key (which we will use with ssh -i) and key.pub, which we will copy to the remote machine. Let us copy key.pub, then on the remote machine, we will add it into /root/.ssh/authorized_keys:

```
echo "ssh-rsa AAAAB...SNIP...M= user@parrot" >> /root/.ssh/authorized_keys
```
