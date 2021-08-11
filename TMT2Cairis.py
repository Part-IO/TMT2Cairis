import tkinter as tk
from tkinter import filedialog

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

    '''Get all relevant parts for a Data Flow Diagram'''
    for child in root.findall('{http://schemas.datacontract.org/2004/07/ThreatModeling.Model}DrawingSurfaceList'):
        for ele in child.findall('{http://schemas.datacontract.org/2004/07/ThreatModeling.Model}DrawingSurfaceModel'):
            '''Get Stencils - Interactor, Process, Data Store, Trust Boundary'''
            for ele2 in ele.findall('{http://schemas.datacontract.org/2004/07/ThreatModeling.Model}Borders'):
                for borders in ele2.findall(
                        '{http://schemas.microsoft.com/2003/10/Serialization/Arrays}KeyValueOfguidanyType'):
                    #stencil = dict.fromkeys(["name", "environment", "from_name", "from_type", "to_name", "to_type"])
                    #stencil["to_name"] = get_element(borders)
                    #stencil["from_type"] = "entity"
                    stencil = get_element(borders)
                    print(stencil)
            '''Get Line - Generic Data Flow, HTTPS'''
            for ele2 in ele.findall('{http://schemas.datacontract.org/2004/07/ThreatModeling.Model}Lines'):
                for lines in ele2.findall(
                        '{http://schemas.microsoft.com/2003/10/Serialization/Arrays}KeyValueOfguidanyType'):
                    # Flows. Unlike stencils, flows have a source and target guids
                    line = get_element(lines)
                    print(line)


if __name__ == '__main__':
    main()
