def modify_device_status(cookie, status):
    print("map %s to %s" % (cookie, status))
    f = open("./data/devices.txt", 'r')
    data = f.read().splitlines()
    f.close()
    for i in range(0, len(data), 2):
        if cookie == data[i]:
            data[i + 1] = status
            break
    f = open("./data/devices.txt", 'w')
    for x in data:
        f.write("%s\n" % x)
    f.close()
