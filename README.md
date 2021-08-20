# TMT2Cairis
## Microsoft Threat Modeling Tool to Cairis Converter
###Explanation

### Usage
1. Download the TMT2Cairis Project (zip, "git clone" ...)
2. Navigate to the directory where you have downloaded the tool
3. 

## Data/Information avaiable from TMT2TD Tool
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
   
   
   
### Possible Problems
1. TMT2Cairis can not handle Files with multiple Environments yet
Add 

