from HTMLTable import (HTMLTable)

def make_bulletin():
    table = HTMLTable()
    table.append_header_rows((
        ('Bulletin',    ''),
        ('User',    'Comment'),
    ))
    table[0][0].attr.colspan = 2

    f = open("./data/comments.txt", 'r')
    all_data = f.read().splitlines()
    n = len(all_data)
    for i in range(0, n, 2):
        table.append_data_rows(((all_data[i], all_data[i + 1]),),)
    f.close()

    table.set_style({
        'border-collapse': 'collapse',
        'word-break': 'keep-all',
        'white-space': 'nowrap',
        'font-size': '16px',
    })
    table.set_cell_style({
        'border-color': '#000',
        'border-width': '1px',
        'border-style': 'solid',
        'padding': '8px',
    })

    html = table.to_html()
    with open("./pages/bulletin.html", "w") as f:
        f.write(html)
        f.write("\n<hr><br>\n")
        f.write("<form method=\"post\">\n")
        f.write("<label for=\"cmt\"><b>Comment</b></label><br>\n<input type=\"text\" placeholder=\"Your comment\" name=\"cmt\" id=\"cmt\" required> <button type=\"submit\">Submit</button>\n</form>\n")
        f.write("<hr>\n")
        f.write("<br>\n<form method=\"post\">\n<button type=\"submit\">Logout</button>\n</form>\n")

if __name__ == '__main__':
    # This code won't run if this file is imported.
    make_bulletin()
