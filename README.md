# Detect SSH failed attempts
Curious to know who is trying to get into your server via SSH?

Log in your Linux server, run this command in your terminal or clone this repository and execute the python file.

```bash
wget https://raw.githubusercontent.com/philipperemy/ssh-failed-attempts/master/ssh.py && clear && python3.6 ssh.py
```

If your server receives a lot of attacks, you might consider to ban those IPs automatically. More info [fail2ban](https://www.linode.com/docs/security/using-fail2ban-to-secure-your-server-a-tutorial/).

Here is an example of output:

```
*******************************
** SSH ATTACKS COUNTER TOOL  **
*******************************
Found 5 log files. It might take up to 1 minute to complete...
- /var/log/auth.log.2.gz
- /var/log/auth.log.4.gz
- /var/log/auth.log.1
- /var/log/auth.log
- /var/log/auth.log.3.gz
------- Attackers IPs and their username guesses (most common) -------
117.1.206.233, root            : 9,869
117.1.206.233, mail            : 9,865
150.107.188.120, root          : 5,876
218.92.0.189, root             : 5,406
218.92.0.195, root             : 4,869
TOTAL                          : 183,549

------- Attackers IPs (most common) -------
117.1.206.233                  : 19,734
150.107.188.120                : 5,876
218.92.0.189                   : 5,406
218.92.0.195                   : 4,869
218.92.0.200                   : 4,600
TOTAL                          : 183,549

------- Attackers username guesses (most common) -------
root                           : 172,993
mail                           : 9,895
backup                         : 217
nobody                         : 78
sys                            : 54
TOTAL                          : 183,549
Dumped result to ssh-result/ip_user.json.
Dumped result to ssh-result/ip.json.
Dumped result to ssh-result/user.json.
```
