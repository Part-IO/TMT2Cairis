# TMT2Cairis
## Microsoft Threat Modeling Tool to Cairis Converter



## General Structure of the XML (to_convert) 

### Relevant for DFD (Data Flow Diagram)

    
|                    | XML-Reference     | Parent Folder|
|--------------------|-------------------|--------------|
|Data Store & Entity |assets             |riskanalysis  |
|Data Flow           |dataflow           |dataflows     |
|Trust Boundary      |trust_boundary     |dataflows     |
|Process             |usecase            |goals         |

### Relevant Information
   - Data Store &rarr 
        - description, significance, security_property  is ignored
        - asset_association (environment, head_name, head_nav, head_adornment, head_nry, head_role, tail_role, tail_nry,
     tail_adornment, tail_nav, tail_name) is ignored as well
   - Entity &rarr name, short_code, type, is_critical
        - description, significance, security_property  is ignored
   - Data Flow &#8594; name, environment, from_name, from_type, to_name, to_type (Detailinfos)
   - Trust Boundary &#8594; description, trust_boundary_environment(trust_boundary_component (name, type))
   - Process &#8594;



