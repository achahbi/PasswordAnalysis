import string
import re
from rstr import xeger
import sqlite3
from sqlite3 import Error
import random
from datetime import datetime as dt
verbos=True
###################### DATA SET GENERATION
def create_DataSetFromReg(fileName,regexp,length):############ SOLUTION TO CHOICE 5 :/
    with open(fileName,mode="w",encoding="UTF_8",newline="") as destination:
        for i in range(length):
            x=xeger(regexp)
            destination.write(x+"\n")
# Test Call
#create_DataSetFromReg("data.txt",r'[\x00-\x7F]{6,16}$',500)
#create_DataSetFromReg("data1.txt",r'\w{6,16}$',500)
###################### Data base stuff
def create_db(path):
    try:
        conn=sqlite3.connect(path)
        c=conn.cursor()
        c.execute(''' CREATE TABLE PASSWORDS_FILE_DETAILS
                  ('LABEL' text,[TAG] text,[VALUE] INTEGER)''')
        ### Table content description
        ### Label             ,tage       ,Integer
        ### File              ,detailLabel,value
        ### Password Strength , strength  ,number
        ### Char usage        ,ASCII code ,number
        ### Lengths Usage     ,Length     ,number of passwords having this length
        ### Char usage        ,ASCII code ,number
        ### Dangerous Chars   ,Line       ,the dangerous char ASCII code
        conn.commit()        
        print("+ New data base created :",path)
    except Error as e:
        print(e)
    finally:
        conn.close
def insertData(db,data):
    try:
        conn=sqlite3.connect(db)
        c=conn.cursor()
        c.executemany("INSERT INTO PASSWORDS_FILE_DETAILS VALUES (?,?,?)",data)
        conn.commit()
    except Error as e:
        print("BOOOM"*10)
        print(e)
    finally:
        conn.close
def getByLabel(db,label):
    try:
        data=[]
        conn=sqlite3.connect(db)
        c=conn.cursor()
        print("+select TAG,VALUE from PASSWORDS_FILE_DETAILS WHERE Label like '{}'\n".format(label))
        for row in c.execute("select TAG,VALUE from PASSWORDS_FILE_DETAILS WHERE Label like '{}'".format(label)):
            data.append(row)
    except Error as e:
        print(e)
    finally:
        conn.close
        return data
def getData(db,query):
    try:
        data=[]
        conn=sqlite3.connect(db)
        c=conn.cursor()
        for row in c.execute(query):
            data.append(row)
        
    except Error as e:
        print(e)
    finally:
        conn.close
        return data
############################################
###################### Other functions
def getdifferentChars(password):
    ## This method return the password after removing duplicate chars
    px=[]
    for c in password:
        if c not in px:
            px.append(c)
    #if(verbos):print(px)
    return "".join(px)
def getpasswordStrengh(password):
    patternVeryStrong='^(?=.*[a-z])(?=.*[A-Z].*[A-Z])(?=.*[0-9].*[0-9])(?=.*[^a-zA-Z0-9])(?=.{8,})'
    patternStrong='^(?=.*[a-z])(?=.*[A-Z])(?=.*[0-9])(?=.*[^a-zA-Z0-9])(?=.{6,})'
    patternMedium='^(?=.*[a-z])(?=.*[A-Z])(?=.*[0-9])(?=.{6,})'
    if(re.match(patternVeryStrong,password)):
        return "VeryStrong"
    elif(re.match(patternStrong,password)):
        return "Strong"
    elif(re.match(patternMedium,password)):
        return "Medium"
    else:
        return "Weak"
############################################
###################### Main extraction
def getFileData(file):
    with open(file,mode="r") as source:
        data=[]
        maj=0
        mins=0
        numbers=0
        symboles=0
        maxlength=0
        minlength=1000
        moyenne=0
        numberofLines=0
        taillesenchars=0
        passwordStrength={
                "VeryStrong":0,
                "Strong":0,
                "Medium":0,
                "Weak":0
            }
        dangerousChars=[]
        charusage=[0]*128
        lengths=[0]*100
        for password in source:
            numberofLines=numberofLines+1
            if(verbos and (numberofLines % 100 ==0)): print("Processing Line {}------->".format(numberofLines))
            password=password.strip("\n")
            if len(password) > maxlength:
              maxlength=len(password)
            if len(password)<minlength:
                minlength=len(password)
            ###### Statistics about Passwords lengths
            lengths[len(password)]=lengths[len(password)]+1
            ###### Counting total number of chars in the file (For Ratios)
            taillesenchars=taillesenchars+len(password)
            ###### UPDATE PASSWORD STRENGHT STATISTICS
            ps=getpasswordStrengh(getdifferentChars(password))
            passwordStrength[ps]=passwordStrength[ps]+1
            for c in password:
                # Update char usage count
                charusage[ord(c)]=charusage[ord(c)]+1
                # Verification Upper 65-90
                if c.isupper():
                    maj=maj+1
                # Verification Lower    97-122
                elif c.islower():
                    mins=mins+1
                # Verification Numeric is
                elif c.isnumeric():
                    numbers=numbers+1
                # Donc symboles
                else:
                    ## CHECKING FOR ASCII Control Chars
                    if (ord(c) in range(32)) or (ord(c)==127):
                        dangerousChars.append([numberofLines,ord(c)])
                    symboles=symboles+1
        ############## File related data
        data.append(["File","Nombre de majiscules",maj])
        data.append(["File","Nombre de miniscules",mins])
        data.append(["File","Nombre de symboles",symboles])
        data.append(["File","Taille password plus long",maxlength])
        data.append(["File","Taille password plus petit",minlength])
        data.append(["File","Nombre de miniscules",mins])
        data.append(["File","Nombre de lignes",numberofLines])
        data.append(["File","Nombre de caractères",taillesenchars])
        ############## Password strength related data
        data.append(["Password strength","Very Strong ",passwordStrength["VeryStrong"]])
        data.append(["Password strength","Strong ",passwordStrength["Strong"]])
        data.append(["Password strength","Medium ",passwordStrength["Medium"]])
        data.append(["Password strength","Weak ",passwordStrength["Weak"]])
        ############## Data related to charusage
        for i in range(128):
            data.append(["Char Usage",str(i),charusage[i]])
        ############## Data related to Lengths
        for i in range(100):
            if(lengths[i]!=0):
                data.append(["Lengths Usage",str(i),lengths[i]])
        ############## Data related to Control Chars
        for x in dangerousChars:
            data.append(["Dangerous Chars",str(x[0]),str(x[1])])
        ############# Create a database
        # DB NAME
        when=dt.now()
        dbName=when.strftime("PasswordsAnalysis_%Y-%m-%d_%H-%M-%S.db")
        create_db(dbName)
        if(verbos):print("+ DataBase {} Created ".format(dbName))
        ############# Insert Data to db
        insertData(dbName,data)
        if(verbos):print("+ Data inserted to DB {} successfully ".format(dbName))
        #######################
        print(" TotalLines | TotalChars | Majiscules | Miniscules | Numbers    | Symboles   | maxlength  | minLength ")
        print("-"*104)               
        print(" {:10} | {:10} | {:10} | {:10} | {:10} | {:10} | {:10} | {:10}".format(numberofLines,taillesenchars,maj,mins,numbers,symboles,maxlength,minlength))
        return dbName
# getFileData("data.txt") test

