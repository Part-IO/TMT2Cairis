import dict2xml


# Convert the data from the Threat Dragon Map to a Cairis Map
def convert(model):
    # 1. Set general Environment
    mxfile = dict.fromkeys(["diagram"])
    mxfile["diagram"] = dict.fromkeys(["mxGraphModel"])
    mxfile["diagram"]["mxGraphModel"] = dict.fromkeys(["root"])
    mxfile["diagram"]["mxGraphModel"]["root"] = dict.fromkeys(["mxCell", "object"])
    # 2. Set general attributes
    mxCell = [{"id": "0"}, {"id": "1", "parent": "0"}]
    mxfile["diagram"]["mxGraphModel"]["root"]["mxCell"] = mxCell
    # 3. Redefine the imported model from TMT2TD for a easier use
    sub_model = model["detail"]["diagrams"][0]["diagramJson"]["cells"]
    for cell in sub_model:
        # We have to seperate between the differents types
        typ = cell["type"]
        # Because Actor and Datastore are both Assets(Entities) in Cairis we put them together
        if typ == "tm.Actor" or typ == "tm.Store":
            object = dict.fromkeys(["label", "type", "id"])
            object["label"] = cell["name"]
            object["id"] = cell["id"]
            # Because we handle two types we have to seperate
            if typ == "tm.Actor":
                object["type"] = "entity"
            else:
                object["type"] = "datastore"
            # Now we can add the Object to the XML File
            mxfile["diagram"]["mxGraphModel"]["root"]["object"] = object
            # New Subdirectory with mxCell
            mxCell = dict.fromkeys(["style", "vertex"])
            # Both, Style and Vertex are predefined
            mxCell["style"] = "html=1;dashed=0;whitespace=wrap;shape=partialRectangle;right=0;left=0;"
            mxCell["vertex"] = "1"
            mxfile["diagram"]["mxGraphModel"]["root"]["object"]["mxCell"] = mxCell
            # Need of another sub Direcrory
            mxGeometry = dict.fromkeys(["x", "y", "width", "height", "as"])
            # X any Y value are stored in an own dict position
            position = cell["position"]
            mxGeometry["x"] = position["x"]
            mxGeometry["y"] = position["y"]
            # Width and Height are stored in an own dict size
            size = cell["size"]
            mxGeometry["width"] = size["width"]
            mxGeometry["height"] = size["height"]
            # As is once more predefined
            mxGeometry["as"] = "geometry"
            mxfile["diagram"]["mxGraphModel"]["root"]["object"]["mxCell"]["mxGeometry"] = mxGeometry


        elif typ == "tm.Flow":
            pass
            """# 1. Create corresponding dict. with relevant information
            line = dict.fromkeys(["name", "environment", "from_name", "from_type", "to_name", "to_type"])
            # 2. Add corresponding name
            line["name"] = cell["name"]
            # 3. Because of missing information we define the environment for all lines with day
            line["environment"] = "Day"
            # 4. For lines we need a source and his Type with a Globally Unique Identifier
            for stencil in sub_model:
                line_source = cell["source"]
                if stencil["id"] == line_source["id"]:
                    line["from_name"] = stencil["name"]
                    line["from_type"] = type_convert(stencil["type"])  # Typ muss hier wohl noch angepasst werden!!!
                    break
                else:
                    pass
            # 5. As well as the target and his type
            for stencil in sub_model:
                line_target = cell["target"]
                if stencil["id"] == line_target["id"]:
                    line["to_name"] = stencil["name"]
                    line["to_type"] = stencil["type"]  # Typ muss hier wohl noch angepasst werden!!!
                    break
                else:
                    pass
            # 6. All relevant information are now included, so we can pass it to the XML-Convert
            xml_components(line)
            """

        elif typ == "tm.Boundary":
            pass
            """
            boundary = dict.fromkeys(["name", "id", "x", "y", "width", "height"])
            boundary["name"] = cell["name"]
            boundary["id"] = cell["id"]
            # TODO

            collection["type"] = "trustboundary"
            collection["element"] = boundary
            """

        elif typ == "tm.Process":
            pass
            """
            process = dict.fromkeys(["name", "author", "code"])
            process["name"] = cell["name"]
            # Because of missing information of the author - predefined TMT2Cairis
            process["author"] = "TMT2Cairis"
            # Because of missing information of the short Code - predefined as PCS (Process)
            process["code"] = "PCS"
            """

        elif typ == "summary":
            pass
        else:
            print("Error")
    print("Here I am ")
    print(dict2xml.dict2xml(mxfile, "mxfile"))
