def add_comment(user, content):
    f = open("./data/comments.txt", 'a')
    f.write("%s\n%s\n" % (user, content))
    f.close()

def add_user(user, password):
    f = open("./data/users.txt", 'a')
    f.write("%s %s\n" % (user, password))
    f.close()

def add_device(cookie):
    print("add %s" % cookie)
    f = open("./data/devices.txt", 'a')
    f.write("%s\n*\n" % cookie)
    f.close()

if __name__ == '__main__':
    # This code won't run if this file is imported.
    u, c = input().split()
    add_comment(u, c)