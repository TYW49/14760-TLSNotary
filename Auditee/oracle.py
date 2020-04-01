from flask import request, Flask, abort, jsonify, send_from_directory
import os, json, requests
import notarize
import reviewer
import sys
reload(sys)
sys.setdefaultencoding("utf-8")

app = Flask(__name__)

PROOF_DIR = "proofs"
data_dir = os.path.dirname(os.path.realpath(__file__))
PROOF_DIR = os.path.join(data_dir, PROOF_DIR)

oracle_modulus = "A9A42A3EA62554863CE1FB13CE49A7378E3C77AC5B3E560E14E57E6BBAEAD64334EB0C7D43F29610277F3C9EC127E51228996BFB38154F8D35667F645DE5B9C4D85B5D5F5579CDE8E079C8FA898CFB809F7D43A5DA8D0BED4AD61D46092EB09C1A21FF8B65C861FC923D3D644A67C363C79E27CD90C49ECF53B11B4B7B821523FF29E0282203EE01B13AFE8BBED62A664AC8EB7B1485960DE4B24FC36407D7D495F62B90ED4C88E7AE10DE755823F2093A983E36D41598E6EB28238C8FBA8F7B1E47AA35DF72D5C8BF60F1E26BE5135ED6A99DB0A3BD0372F6658ECC7FBC09E9F06B21CD1665BE4A3ADD2A645E8118B33FE01610883924EBB8A3F772153D17FABC64573588015D4CE8C65775574FDBE1D5E692FE5423BC92F4D2D8749387DB0D87EAE1037318FE3A62D69AAFDA08999981BA7F50B1B20BA85045689523B9D5822BC55AAEEC93DBDF60B9970F016FB0E379D42E2F8B639534661CA9B9A70ED52E94546C4DC49E2C6FE2658B97929DCC71E4975B79896B1C90BF165EEC26EA671B5BFD59BDA6719B49B9EB72E6249E989336A9A60823A545C7D86AF5AE5029ED55AFF05B1797675326227638AF828C1FBA881504C792AF5B23CECEFB626C0CBACD9AEBD77029A958960CD79C969DD992FC2FA07973D5295AD70978B8C477E204827D5BEABB0248CDBFDC23F5D600270E9AC628ED822D83C7BD794561197E120E51"

@app.route('/generate', methods=['POST'])
def generate():
    if request.method == 'POST':
        args = request.json
        print("args:" + json.dumps(args))
        header = args.get("header")
        target = args.get('target')
        try:
            ok, prooffile = notarize.generate(target, header)
        except Exception as e:
            print(e)
            return "The cipher suites of this server are not supported", 500
        if ok:
            return prooffile, 200

    return result, 500

@app.route('/download/<filename>', methods=['GET', 'POST'])
def download(filename):
    """Download a file."""
    return send_from_directory(PROOF_DIR, filename, as_attachment=True)


@app.route('/upload', methods=['POST'])
def upload(filename):
    """Upload a file."""

    date = time_str = time.strftime('%d-%b-%Y-%H-%M-%S-', time.gmtime())
    session_id = ''.join(random.choice(string.ascii_lowercase+string.digits) for x in range(10))
    filename = date + session_id +".pgsg"
    with open(os.path.join(PROOF_DIR, filename), 'wb') as fp:
        fp.write(request.data)

    # Return 201 CREATED
    return filename, 201

@app.route('/review/<filename>', methods=['GET', 'POST'])
def review(filename):
    filepath = os.path.join(PROOF_DIR, filename)
    ok, result, html = reviewer.review(filepath)
    if ok:
        return result, 200
    return result, 200

@app.route('/convert/<filename>', methods=['GET', 'POST'])
def convert(filename):
    filepath = os.path.join(PROOF_DIR, filename)
    ok, result = reviewer.convert(filepath)
    if ok:
        return result, 200
    return result, 200

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=False)
