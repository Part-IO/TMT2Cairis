import tkinter as tk
from tkinter import filedialog

import lxml.builder
import lxml.etree as ET

ele_namespace = {'b': 'http://schemas.datacontract.org/2004/07/ThreatModeling.KnowledgeBase'}
any_namespace = {'a': 'http://schemas.microsoft.com/2003/10/Serialization/Arrays'}

# get and element (or cell)
def get_ele_prop(ele, prop_name):
    # element properties are at this level
    for props in ele.findall('{http://schemas.datacontract.org/2004/07/ThreatModeling.Model.Abstracts}Properties'):
        for types in props.findall('.//a:anyType', any_namespace):
            # get all child elements of anyType element, all properties located here
            for dis_name in types.findall('.//b:DisplayName', ele_namespace):
                temp_prop = dis_name.text
                # selection = types.find('.//b:SelectedIndex', ele_namespace)
                if temp_prop == prop_name:
                    for val in types.findall('.//b:Value', ele_namespace):
                        value = val.text
                    return value
    return None


def get_element(ele):
    for ele4 in ele.findall('{http://schemas.microsoft.com/2003/10/Serialization/Arrays}Value'):
        # find element type and get cell dict format
        name = get_ele_prop(ele4, 'Name')
    return name


# get the summary info for the model
# missing: Assumptions, ExternalDependencies,
def get_sum(_root):
    _sum = dict.fromkeys(['title', 'owner', 'description'])
    for sum in _root.findall('{http://schemas.datacontract.org/2004/07/ThreatModeling.Model}MetaInformation'):
        for _title in sum.findall('{http://schemas.datacontract.org/2004/07/ThreatModeling.Model}ThreatModelName'):
            title = _title.text
        for _owner in sum.findall('{http://schemas.datacontract.org/2004/07/ThreatModeling.Model}Owner'):
            owner = _owner.text
        for _desc in sum.findall(
                '{http://schemas.datacontract.org/2004/07/ThreatModeling.Model}HighLevelSystemDescription'):
            desc = _desc.text
    if not title:
        title = "TMT import"
    if not desc:
        desc = "Imported from Microsoft Threat Modeling Tool .tm7 file"
    _sum['title'] = title
    _sum['owner'] = owner
    _sum['description'] = desc
    return _sum


# get the contributors as a list
def get_contribs(_root):
    for sum in _root.findall('{http://schemas.datacontract.org/2004/07/ThreatModeling.Model}MetaInformation'):
        for _contribs in sum.findall('{http://schemas.datacontract.org/2004/07/ThreatModeling.Model}Contributors'):
            if _contribs.text is None:
                return None
            contribs = _contribs.text.split(',')
    contrib_list = []
    c_dict = dict.fromkeys(['name'])
    for p in contribs:
        c_dict['name'] = p
        contrib_list.append(c_dict)
    return contrib_list


def xml_dfd(stencil):
    root = lxml.builder.ElementMaker()
    model = root.cairis_model
    dataflows = root.dataflows
    dataflow = root.dataflow
    # dataflow_asset = root.dataflow.dataflow_asset
    for x in stencil:
        the_doc = model(
            dataflows(
                dataflow(name=stencil["name"],
                         environment="Day",
                         from_name="PLC",
                         from_type="entity",
                         to_name="Raise Alarm",
                         to_type="process"
                         )
            )
        )
        print(lxml.etree.tostring(the_doc, pretty_print=True))


def generate_dfd_xml(cells):
    root = lxml.builder.ElementMaker()
    model = root.cairis_model
    dataflows = root.dataflows
    dataflow = root.dataflow
    dataflow_asset = root.dataflow.dataflow_asset
    dfd_xml = 'model(dataflows('
    for cell in cells:
        if cells["type"] == "stencil":

            dataflow = dataflow(name=cell["name"],
                                environment="Day",
                                from_name="PLC",
                                from_type="entity",
                                to_name="Raise Alarm",
                                to_type="process")
            dfd_xml = dfd_xml + dataflow
        elif cells["type"] == "line":
            dataflow_asset(name=cell["name"])
            dfd_xml = dfd_xml + dataflow_asset
        else:
            dfd_xml = dfd_xml + '))'


def line(line):
    cell = get_flow_points(line)
    stencil = dict.fromkeys(["name", "environment", "from_name", "from_type", "to_name", "to_type"])
    stencil["name"] = get_element(line)
    ' Value Environment is predefined because of missing information '
    stencil["Environment"] = "Day"
    stencil["from_name"] = cell["source"]
    stencil["from_type"] = "TODO"
    stencil["to_name"] = cell["target"]
    stencil["to_type"] = "TODO"

    print(stencil)


def stencil(cells):
    # Find type / Separate between Data Store, Entity, Trust Boundary, Process
    pass


def main():
    # Open Window to interact
    root = tk.Tk()
    root.withdraw()
    # Try to find the related TM7 Diagram
    try:
        file_path = filedialog.askopenfilename(parent=root, filetypes=[("MS threat model files", "*.tm7")])
    except FileNotFoundError:
        print('Must choose file path, quitting... ')
        quit()
    if not file_path:
        print('Must choose file path, quitting... ')
        quit()
    # Close Window
    root.destroy()
    tree = ET.parse(file_path)
    root = tree.getroot()

    '''1. Get all relevant parts for a Data Flow Diagram'''
    for child in root.findall('{http://schemas.datacontract.org/2004/07/ThreatModeling.Model}DrawingSurfaceList'):
        for ele in child.findall('{http://schemas.datacontract.org/2004/07/ThreatModeling.Model}DrawingSurfaceModel'):
            '''Get Stencils - Interactor, Process, Data Store, Trust Boundary'''
            for ele2 in ele.findall('{http://schemas.datacontract.org/2004/07/ThreatModeling.Model}Borders'):
                for borders in ele2.findall(
                        '{http://schemas.microsoft.com/2003/10/Serialization/Arrays}KeyValueOfguidanyType'):
                    stencil(borders)
            '''Get Line - Generic Data Flow, HTTPS'''
            for ele2 in ele.findall('{http://schemas.datacontract.org/2004/07/ThreatModeling.Model}Lines'):
                for lines in ele2.findall(
                        '{http://schemas.microsoft.com/2003/10/Serialization/Arrays}KeyValueOfguidanyType'):
                    # Flows. Unlike stencils, flows have a source and target, so we need a helping function
                    line(lines, cell)


if __name__ == '__main__':
    main()
