# TMT2Cairis
## Microsoft Threat Modeling Tool to Cairis Converter
###Explanation

### Usage/Installation

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
   
   
   
### Probleme
Prozesse oder Entities mit dem selben Namen können Probleme für das spätere skizzieren werden


Reihenfolge der 

