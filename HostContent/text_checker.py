import string

with open("file1.txt", "r") as f1:
    content1 = f1.read()

with open("file2.txt", "r") as f2:
    content2 = f2.read()

words1 = [word.strip(string.punctuation) for word in content1.lower().split()]
words2 = [word.strip(string.punctuation) for word in content2.lower().split()]

set1 = set(words1)
set2 = set(words2)

common = set1 & set2

with open("result.txt", "w") as f:
    f.write("\n".join(common))