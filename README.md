# TMT2Cairis

## Summary
The "Microsoft Threat Modeling Tool to Cairis" (TMT2Cairis) converter is able to generate an XML file optimized for 
Cairis from a TM7 file for the automated creation of a data flow diagram. For later import in Cairis, please use 
the "diagrams.net" import (See Usage 9.)

## Usage
1. Download the TMT2Cairis Project (zip, "git clone" ...)
2. Navigate to the directory where you have downloaded the tool (Windows - CMD or UBuntu Shell)
3. Start the TMT2Cairis.py file with python. (Python3 is required)
            
    ```console
    python TMT2Cairis.py or
    python3 TMT2Cairis.py
    ```
4. Your File-Explorer should open
5. Navigate to the file to be transformed (For testing you can use the sample-TM7 Files in TMT2Cairis\tm7_Samples)
6. The TMT2Cairis Tool will now generate you a XML File in the same directory (source directory)
7. Open your Cairis-Tool or for testing go to https://demo.cairis.org/ (User: test@test.com, PW: test)
8. Navigate to System/Import Model in Cairis
9. Import Model
    - As Model Select : diagrams.net (Data Flow Diagram)
    - File: Select the new generated XML file
    - Environment: Choose your predefined Environment (You can define an environment in UX/Environment)
10. Navigate to Models/Data Flow in Cairis

### Requirements
- Python 3 is required
- Works best with Python 3.8+
- OS with GUI Windows/Ubuntu/Linux Mint/MAC OS (No Arch yet)

### Data/Information avaiable from TMT2TD Tool

|Type                |              |         Avaiable Information from MS TMT               |
|--------------------|--------------|--------------------------------------------------------|
| tm.Actor           |              | label (name), type = "entity", id, x, y, width, height |
| tm.Store           |              |                                                        | 
| tm.Flow            |              | x, y                                                   |
| tm.Boundary        |              | name, id, x, y, width, height                          |
| tm.Process         |              | label(name), type="", id, x, y, width, height          |  



### Necessary Information for Cairis-Tool Convertion
|                    |Class              |Type          |              Necessary Information for Cairis          |
|--------------------|-------------------|--------------|--------------------------------------------------------|
|Entity (incl. Actor)|Assets             |entity        | label (name), type = "entity", id, x, y, width, height |
|Entity - Data Store |Assets             |datastore     | label (name), type = "entity", id, x, y, width, height |
|Data Flow           |Data Flows         |None (mxCell) | x, y                                                   |
|Trust Boundary      |Trust Boundary     |trustboundary | name, id, x, y, width, height                          |
|Process             |Usecase            |usecase       | label(name), type="", id, x, y, width, height          |  
   
   
   
### Limitations and Problems
1. Data Flow Names are ignored because of in Cairis all data flows inside objects are predefined as "undefined flows"
2. TMT2Cairis can not handle Files with multiple Environments yet! Please create an own file for each environment first. 
You can later create and directly import the models in the environment in Cairis (See Usage 9.)
3. In the MS TMT Tool you can create Trust Boundaries as lines. In Cairis a trust boundary at least has to have one 
Process. Data Stores and Entities are also not allowed to be inside a trust boundary
4. Becuase of Cairis Syntax it's not allowed to have a direct data flow between two entities! 

