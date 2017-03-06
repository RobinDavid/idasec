header = '''
<!DOCTYPE html>
<html>
<head>
<style>
body { background-color: white; color:black}
.VIOLATION_UNKNOWN { color: #6f00d6; }
th { font-weight:bold }
table {
    border-collapse: collapse;
}

table, th {
    border: 1px solid black;
}
td, th {
  padding: 5px;
}
/*
td {
    border-bottom: 1px solid #ddd;
}
tr:hover {background-color: #f5f5f5}
*/
tr:nth-child(even) {background-color: #f2f2f2}
</style>
</head>
<body>
'''

trailer = '''
</body>
</html>
'''

BLUE = '#143CCC'
WHITE = '#FFFFFF'
BLACK = '#000000'
GREEN = "#079F00"
RED = "#ff0000"
PURPLE = "#6E15CC"
ORANGE = "#ff5500"


def make_cell(content, bold=False, color=None):
    if not bold and color is None:
        return "<td>%s</td>" % content
    else:
        bold = "" if not bold else "font-weight:bold;"
        color = "" if color is None else "color: %s;" % color
        return "<td style='%s%s'>%s</td>" % (bold, color, content)


class HTMLReport:
    def __init__(self):
        # TODO: detect IDA version to embed or not bootstrap
        self.datas = []

    def add_title(self, title, size=1):
        self.datas.append("<h%d>%s</h%d>" % (size, title, size))

    def add_table_header(self, elts):
        prelude = '''<table class="table table-striped"><tbody><tr>'''
        row = ''.join(['<th>%s</th>' % x for x in elts])
        self.datas.append(prelude+row+"</tr>")

    def add_table_line(self, elts):
        self.datas.append("<tr>"+''.join(elts)+"</tr>")

    def end_table(self):
        self.datas.append("</tbody></table>")

    def generate(self):
        return "%s%s%s" % (header, ''.join(self.datas), trailer)
