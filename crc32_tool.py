# time: CRC32_Tool
# author: iami233
# time: 2023/11/01
# version: v1.0.0
from tqdm import tqdm
from zlib import crc32
from rich.table import Table
from rich.style import Style
from itertools import product
from rich.console import Console
import os, re, string , zipfile, argparse, subprocess

console = Console()
baseDir = os.path.dirname(os.path.abspath(__file__))
PATTERNS = ["4 bytes: (.*?) {", "5 bytes: (.*?) \(", "6 bytes: (.*?) \("]
nolist = {}
count = 0

def crackCrc(secret, size):
    global count
    count += 1
    command = f'python "{os.path.join("src", "crc32.py")}" reverse {secret}'
    result = subprocess.run(command, shell=True, capture_output=True, text=True).stdout
    result = re.findall(PATTERNS[size - 4], result)
    if not result:
        nolist[count] = secret
    return result

def lowCrackCrc(secret):
    dic = string.ascii_letters + string.digits + string.punctuation + ' '
    for i in range(1, 6):
        for res_char in product(dic, repeat=i):
            s = ''.join(res_char)
            if secret == (crc32(bytes(s, 'ascii')) & 0xffffffff):
                return s
    return None

def getCrc32(fileName):
    crcSizeDict = {}
    with zipfile.ZipFile(fileName, 'r') as zipFile:
        for fileInfo in sorted(zipFile.infolist(), key=lambda f: f.filename):
            size = fileInfo.file_size
            file = fileInfo.filename
            crc = hex(fileInfo.CRC)
            if crc != '0x0':
                crcSizeDict[file] = crc, size
    return crcSizeDict

def processFiles(fileDict):
    results = {}
    for secret, size in fileDict.items():
        plainText = []
        if 4 <= size <= 6:
            plainText = crackCrc(secret, size)
        elif 1 <= size <= 3:
            plainText = lowCrackCrc(int(secret, 16))
        results[secret] = plainText
    return results

def processArgs():
    parser = argparse.ArgumentParser(description="CRC32 Hash Cracker")
    parser.add_argument("-f", "--filename", help="Specify the filename to process")
    args = parser.parse_args()
    if not args.filename:
        console.print("Please provide a filename using the -f or --filename option.", style=Style(color="red"))
        return None
    return args.filename

def getFileAndDetailLists(crcSizeDict):
    fileList = {}
    detailList = {}
    for key, value in crcSizeDict.items():
        fileList[key] = value[0]
        detailList[value[0]] = value[1]
    return fileList, detailList

def printTableAndResult(data, fileList, nolist):
    table = Table(show_header=True)
    table.add_column('FILE', style=Style(color="green"))
    table.add_column("CRC32", style=Style(color="blue"))
    table.add_column("TEXT", style=Style(color="cyan"))

    for crc32, text in data.items():
        file = next((file for file, value in fileList.items() if crc32 == value), None)
        if isinstance(text, list):
            text = ",".join(text)
        else:
            text = "".join(text)
        table.add_row(file, crc32, text)

    console.print(table)

    if nolist:
        all_values = ', '.join(nolist.values())
        console.print(f"CRC32 {all_values} have no plain text.", style=Style(color="red"))
        userInput = input("Do you want to brute force the CRC32 hashes without plain text? (y/n): ")
        if userInput.lower() == 'y':
            for key, value in nolist.items():
                console.print(f"Brute forcing CRC32 hash {value}...", style=Style(color="yellow"))
                crack = lowCrackCrc(int(value, 16))
                console.print(f"Brute forcing successful: {crack}", style=Style(color="green"))
                data[value] = [crack]

    data = {key: value for key, value in data.items() if value}
    combinations = list(product(*data.values()))

    if len(combinations) > 5 and combinations:
        userInput = input("Do you want to write all combinations to dict.txt? (y/n): ")
        if userInput.lower() == 'y':
            with open('dict.txt', 'w') as f:
                for i in tqdm(combinations, desc="Writing to dict.txt"):
                    print(''.join(i), file=f)
            with open('output.txt' , 'w') as f:
                print(data, file=f)
            console.print('Write Success', style=Style(color="green"))
        else:
            console.print(''.join(i), style=Style(color="red"))
    else:
        result = ''.join(''.join(texts) for texts in data.values())
        console.print(f'Result: {result}', style=Style(color="green"))

def main():
    filename = processArgs()
    if not filename:
        return
    
    try:
        crcSizeDict = getCrc32(filename)
        fileList, detailList = getFileAndDetailLists(crcSizeDict)
        data = processFiles(detailList)
        if not data:
            console.print("No CRC32 hashes found in the ZIP file.", style=Style(color="red"))
            return
        printTableAndResult(data, fileList, nolist)

    except Exception as e:
        console.print(f"An error occurred: {e}", style=Style(color="red"))

if __name__ == "__main__":
    main()
