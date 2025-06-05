#!/usr/bin/env python3

import subprocess

subprocess.run(['make'], check=True)

# Convert the stages to a JS array literal
stages = open('stages', 'rb').read()

js = 'var stages = new Uint8Array(['
js += ','.join(map(str, stages))
js += ']);\n'
js += '''
stages.replace = function(oldVal, newVal) {
    for (var idx = 0; idx < this.length; idx++) {
        var found = true;
        for (var j = idx; j < idx + 8; j++) {
            if (this[j] != oldVal.byteAt(j - idx)) {
                found = false;
                break;
            }
        }
        if (found)
            break;
    }
    this.set(newVal.bytes(), idx);
};
'''

with open('stages.js', 'w') as f:
    f.write(js)

EXPORTS = [
        {'path': 'stages.js', 'content_type': 'text/javascript; charset=UTF-8'}
]

subprocess.run(['cp', 'stages.js', '..'], check=True)
subprocess.run(['rm', 'stages.js'], check=True)