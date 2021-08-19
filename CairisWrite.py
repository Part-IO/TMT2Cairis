from dict2xml import dict2xml


# Convert the data from the Threat Dragon Map to a Cairis Map
def convert(model, base_name):
    xml = []
    sub_model = model["detail"]["diagrams"][0]["diagramJson"]["cells"]
    mxfile = dict.fromkeys(["mxCell"])
    mxfile["mxCell"] = dict.fromkeys(["id"])
    mxfile["mxCell"]["id"] = "0"
    xml.append(mxfile)
    mxfile = dict.fromkeys(["mxCell"])
    mxfile["mxCell"] = dict.fromkeys(["id", "parent"])
    mxfile["mxCell"]["id"] = "1"
    mxfile["mxCell"]["parent"] = "0"
    xml.append(mxfile)
    # Create dict over dict to later iterate over the types (type not available in all elements)
    for cell in sub_model:
        mxfile = dict.fromkeys(["object"])
        mxfile["object"] = dict.fromkeys("mxCell")
        mxfile["object"]["mxCell"] = dict.fromkeys("mxGeometry")
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
            mxfile["object"] = object
            mxCell = dict.fromkeys(["style", "vertex"])
            # Both, Style and Vertex are predefined
            mxCell["style"] = "html=1;dashed=0;whitespace=wrap;shape=partialRectangle;right=0;left=0;"
            mxCell["vertex"] = "1"
            mxfile["object"]["mxCell"] = mxCell
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
            mxfile["object"]["mxCell"]["mxGeometry"] = mxGeometry
            # Finished with the object we can append it on the xml-array
            xml.append(mxfile)

        elif typ == "tm.Flow":
            object = dict.fromkeys(["label", "assets", "id"])
            object["label"] = cell["name"]
            object["assets"] = cell["name"]
            object["id"] = cell["id"]
            mxfile["object"] = object
            mxCell = dict.fromkeys(["parent", "source", "target", "edge"])
            mxCell["parent"] = "1"
            source = cell["source"]
            mxCell["source"] = source["id"]
            target = cell["target"]
            mxCell["target"] = target["id"]
            mxCell["edge"] = "1"
            mxfile["object"]["mxCell"] = mxCell
            xml.append(mxfile)

        elif typ == "tm.Boundary":
            object = dict.fromkeys(["label", "name", "type", "id"])
            object["label"] = cell["name"]
            object["name"] = cell["name"]
            object["type"] = "trustboundary"
            object["id"] = cell["id"]
            mxfile["object"] = object
            mxCell = dict.fromkeys(["parent", "vertex"])
            mxCell["parent"] = "1"
            mxCell["vertex"] = "1"
            mxfile["object"]["mxCell"] = mxCell
            mxGeometry = dict.fromkeys(["x", "y", "width", "height"])
            source = cell["source"]
            mxGeometry["x"] = source["x"]
            mxGeometry["y"] = source["y"]
            vertices = cell["vertices"]
            # Falls die Boundary ein Rechteck ist
            if len(vertices) == 3:
                max = vertices[1]
                mxGeometry["width"] = (max["x"] - source["x"])
                mxGeometry["height"] = (max["y"] - source["y"])
            else:
                max = vertices[0]
                mxGeometry["width"] = 1
                mxGeometry["height"] = 1
            mxfile["object"]["mxCell"]["mxGeometry"] = mxGeometry
            xml.append(mxfile)

        elif typ == "tm.Process":
            object = dict.fromkeys(["label", "type", "id"])
            object["label"] = cell["name"]
            # Because of missing information of the author - predefined TMT2Cairis
            object["type"] = "process"
            # Because of missing information of the short Code - predefined as PCS (Process)
            object["id"] = cell["id"]
            mxfile["object"] = object
            mxCell = dict.fromkeys(["style", "vertex", "parent"])
            mxCell["style"] = "rounded=1;whiteSpace=wrap;html=1;"
            mxCell["vertex"] = "1"
            mxCell["parent"] = "1"
            mxfile["object"]["mxCell"] = mxCell
            mxGeometry = dict.fromkeys(["x", "y", "height", "width"])
            position = cell["position"]
            mxGeometry["x"] = position["x"]
            mxGeometry["y"] = position["y"]
            size = cell["size"]
            mxGeometry["height"] = size["height"]
            mxGeometry["width"] = size["width"]
            mxfile["object"]["mxCell"]["mxGeometry"] = mxGeometry
            xml.append(mxfile)
        else:
            print("Error")
    write(xml, base_name)


# Import Data Flow dict and convert to data flow xml syntax
def createXML(xml_array):
    for xml in xml_array:
        print(dict2xml(xml))
    return


def write(xml_array, base_name):
    file_path = base_name + '.xml'
    with open(file_path, 'w') as xml:
        xml.write('<?xml version="1.0" encoding="UTF-8"?>')
        xml.write('<mxfile ><diagram ><mxGraphModel ><root >')
        for cell in xml_array:
            xml.write((dict2xml(cell)))
        xml.write('</root></mxGraphModel></diagram></mxfile>')
