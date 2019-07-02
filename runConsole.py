######## passwordFileAnalysis
from passwordFileAnalysis import *
CURRENTDB=""
def printOptions():
    print("")
    print("*"*100)
    print("*"*100)
    print("*"*100)
    print("*"*100)
    print(" █████    	 █████         ")
    print("██   ██ 	██   ██        ")
    print("██████  	███████        ")
    print("██		██   ██        ")
    print("██ASSWORDS█	██   ██NALYSIS V1.0 ")
    print("")
    print("*"*100)
    print("*"*100)
    print("*"*100)
    print("*"*100)
    print("0 * Create Test Data")
    print("1 * Process a new File")
    if(CURRENTDB!=""):
        print("2 * Display default statistics")
        print("3 * Run a query on the dataBase")
    print("q * Leave")
def createTestData():
    print("+ This menu allow you to create test data using regex")
    length=int(input("--> Please insert number of lines desired   :"))
    filename=input("--> Please insert File Name                   :\n")
    regex=input("--> Please insert a regex (type D for default):\n")
    if(regex.lower()=="d"):
        regex='\w{6,16}$'
    create_DataSetFromReg(filename,regex,length)
    print("+ File {} created successfully".format(filename))
def processFile():
    global CURRENTDB
    print("+ This menu allow you to create statistics database from file")
    filename=input("--> Please insert File Name                   :\n")
    CURRENTDB=getFileData(filename)
    return None
def DisplayDefaults():
    #### Display File related details
    data=getByLabel(CURRENTDB,"File")
    print("   WHAT                       | VALUE ")
    print("-"*36)
    for c in data:
        print(" {:28} | {:8}".format(c[0],c[1]))
    data=getByLabel(CURRENTDB,"Password Strength")
    print("   Password Strength          | Number of passwords ")
    print("-"*36)
    for c in data:
        print(" {:28} | {:8}".format(c[0],c[1]))
    ##### Top 5 most used Chars
    qr="select TAG,VALUE from PASSWORDS_FILE_DETAILS WHERE Label like 'Char usage' order by VALUE DESC LIMIT 5"
    data=getData(CURRENTDB,qr)
    print("TOP 5 MOST USED CHARS")
    print("CHAR       |ASCII CODE | Number")
    print("-"*32)
    for c in data:
        print("{:12}|{:12}|{}".format(chr(int(c[0])),c[0],c[1]))
    ##### Top 5 most used Lengths
    qr="select TAG,VALUE from PASSWORDS_FILE_DETAILS WHERE Label like 'Lengths Usage' order by VALUE DESC LIMIT 5"
    data=getData(CURRENTDB,qr)
    print("TOP 5 MOST USED Lengths")
    print("Length | Number")
    print("-"*16)
    for c in data:
        print("{:8}|{}".format(c[0],c[1]))
    ##### Dangerous Chars
    qr="select TAG,VALUE from PASSWORDS_FILE_DETAILS WHERE Label like 'Dangerous Chars'"
    data=getData(CURRENTDB,qr)
    print("CONTROL ASCII CHARS FOUND")
    print("Line | char ASCII CODE")
    print("-"*32)
    for c in data:
        print("{:8}|{}".format(c[0],c[1]))
    return None
def RunQuery():
    #    
    print("+ This menu allow you to run your query on the file remember :")
    print("### Table content description      (PASSWORDS_FILE_DETAILS)                         ")
    print("")
    print("### Label  (Text)     ,TAG(Text)  ,VALUE(Integer )                                        ")
    print("------------------------------------------------------------------------------------")
    print("### File              ,detailLabel,value                                            ")
    print("### Password Strength , strength  ,number                                           ")
    print("### Char usage        ,ASCII code ,number                                           ")
    print("### Lengths Usage     ,Length     ,number of passwords having this length           ")
    print("### Char usage        ,ASCII code ,number                                           ")
    print("### Dangerous Chars   ,Line       ,the dangerous char ASCII code                    ")
    print("------------------------------------------------------------------------------------")
    print(" TABLE NAME: PASSWORDS_FILE_DETAILS")
    req=input("Please enter your query bellow :\n")
    data=getData(CURRENTDB,req)
    #### Display Management
    maxLeng=0
    nbCols=0
    for c in data:
        nbCols=len(c)
        for x in c:
            if len(str(x))>maxLeng:
                maxLeng=len(str(x))
    disp=""
    for i in range(nbCols):
        disp=disp+"{c["+str(i)+"]:"+str(maxLeng)+"}|"
    for c in data:
        print(disp.format(c=c))
    return None
    
def main():    
    while True:
        printOptions()
        choice=input("Please type your choice :")
        if(choice=="0"):
            createTestData()
            input("Press [Enter] to continue")
        elif(choice=="1"):
            processFile()
        elif(choice=="2"):
            DisplayDefaults()
        elif(choice=="3"):
            RunQuery()
        elif(choice=="q"):
            return None
        input("Press [Enter] to continue")
        
main()
