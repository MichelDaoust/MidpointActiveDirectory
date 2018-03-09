﻿/**
 *
 * Copyright (c) 2013 Salford Software Ltd All rights reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *     http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
**/

using System;
using System.Configuration;
using System.ServiceModel;
using System.Xml;
using PasswordFilterProcessor.MidpointModel3WebService;

// Author Matthew Wright
namespace PasswordFilterProcessor
{
    class ChangePassword
    {
        #region Constants

        private const string NS_MODEL = "http://midpoint.evolveum.com/xml/ns/public/model/model-3";
        private const string NS_COMMON = "http://midpoint.evolveum.com/xml/ns/public/common/common-3";
        private const string SEARCHUSER_NS = "http://prism.evolveum.com/xml/ns/public/query-3";
        private const string COMMON_PATH = "path";
        private const string COMMON_VALUE = "value";
        private const string CLEAR_VALUE = "clearValue";
        private static readonly string ADM_USERNAME = Encryptor.Decrypt(ConfigurationManager.AppSettings["AdminUserName"]);
        private static readonly string ADM_PASSWORD = Encryptor.Decrypt(ConfigurationManager.AppSettings["AdminPassword"]);
//        private static readonly string ADM_USERNAME = ConfigurationManager.AppSettings["AdminUserName"];
//        private static readonly string ADM_PASSWORD = ConfigurationManager.AppSettings["AdminPassword"];
        private static readonly string DEFAULT_ENDPOINT_URL = ConfigurationManager.AppSettings["DefaultEndpoint"];

        private static XmlQualifiedName USER_TYPE = new XmlQualifiedName("UserType", NS_COMMON);



        #endregion


        private static ItemPathType createItemPathType(string path)
        {
            ItemPathType rv = new ItemPathType();
            rv.Value = "declare default namespace '" + NS_COMMON + "'; " + path;
            return rv;
        }


        private static SearchFilterType createNameFilter(String name)
        {
            PropertyComplexValueFilterClauseType clause = new PropertyComplexValueFilterClauseType();
            clause.path = createItemPathType("name");
            clause.Items = new Object[] { name } ;

            SearchFilterType filter = new SearchFilterType();
            filter.Item = clause;
            filter.ItemElementName = ItemChoiceType1.equal;
            return filter;
        }


        private static MidpointModel3WebService.ObjectType getOneObject(MidpointModel3WebService.searchObjectsResponse response, String name)
        {
            MidpointModel3WebService.ObjectType[] objects = response.objectList.@object;
            if (objects == null || objects.Length == 0)
            {
                return null;
            }
            else if (objects.Length == 1)
            {
                return (MidpointModel3WebService.ObjectType)objects[0];
            }
            else
            {
                throw new InvalidOperationException("Expected to find a object with name '" + name + "' but found " + objects.Length + " ones instead");
            }
        }


        /// <summary>
        /// Searches for the given user using the given Midpoint model port.
        /// Returns the UserType object for the user if they exist.
        /// </summary>
        /// <param name="modelPort">The model port used to run search Midpoint.</param>
        /// <param name="username">The username to search for.</param>
        /// <returns>The UserType object for the requested user, or null if not found.</returns>

        public static MidpointModel3WebService.UserType searchUserByName(MidpointModel3WebService.modelPortType modelPort, String username)
        {
            MidpointModel3WebService.QueryType query = new MidpointModel3WebService.QueryType();
            query.filter = createNameFilter(username);

            MidpointModel3WebService.searchObjects request = new MidpointModel3WebService.searchObjects(USER_TYPE, query, null);
            MidpointModel3WebService.searchObjectsResponse response = modelPort.searchObjects(request);
            return (MidpointModel3WebService.UserType)getOneObject(response, username);
        }


        private static ProtectedStringType createProtectedStringType(string clearValue)
        {
            ProtectedStringType rv = new ProtectedStringType();
            rv.clearValue = clearValue;
            return rv;
        }


        public static void changeUserPassword(modelPortType modelPort, String oid, String newPassword)
        {
            ItemDeltaType passwordDelta = new ItemDeltaType();
            passwordDelta.modificationType = ModificationTypeType.replace;
            passwordDelta.path = createItemPathType("credentials/password/value");
            passwordDelta.value = new object[] { createProtectedStringType(newPassword) };

            ObjectDeltaType deltaType = new ObjectDeltaType();
            deltaType.objectType = USER_TYPE;
            deltaType.changeType = ChangeTypeType.modify;
            deltaType.oid = oid;
            deltaType.itemDelta = new ItemDeltaType[] { passwordDelta };

            executeChanges request = new executeChanges(new ObjectDeltaType[] { deltaType }, null);
            executeChangesResponse response = modelPort.executeChanges(request);
            check(response);
        }

        private static void check(executeChangesResponse response)
        {
            foreach (ObjectDeltaOperationType objectDeltaOperation in response.deltaOperationList)
            {
                if (!OperationResultStatusType.success.Equals(objectDeltaOperation.executionResult.status))
                {
                    Console.WriteLine("*** Operation result = " + objectDeltaOperation.executionResult.status + ": "
                        + objectDeltaOperation.executionResult.message);
                }
            }
        }



        #region Public Methods




/*
        public static void changeUserPassword2(MidpointModel3WebService.modelPortType modelPort, string oid, string newPassword)
        {

            MidpointModel3WebService.ModelExecuteOptionsType meot = new MidpointModel3WebService.ModelExecuteOptionsType();
            MidpointModel3WebService.ObjectDeltaType[] odt = new MidpointModel3WebService.ObjectDeltaType[1];

            MidpointModel3WebService.ObjectDeltaType objDeltaType = new MidpointModel3WebService.ObjectDeltaType();
            XmlQualifiedName xqn = new XmlQualifiedName(new MidpointModel3WebService.UserType().GetType().Name, NS_COMMON);
            objDeltaType.objectType = xqn;
            objDeltaType.oid = oid;
            objDeltaType.changeType = MidpointModel3WebService.ChangeTypeType.modify;


            MidpointModel3WebService.ItemDeltaType passwordDelta = new MidpointModel3WebService.ItemDeltaType();
            MidpointModel3WebService.ObjectModificationType userDelta = new MidpointModel3WebService.ObjectModificationType();
            passwordDelta.modificationType = MidpointModel3WebService.ModificationTypeType.replace;
            MidpointModel3WebService.ItemPathType ipt = new ItemPathType();
            ipt.Value = @"declare default namespace 'http://midpoint.evolveum.com/xml/ns/public/common/common-3'; credentials/password/value";
            passwordDelta.path = ipt;
            MidpointModel3WebService.ProtectedStringType pst = new MidpointModel3WebService.ProtectedStringType();
            pst.clearValue = "testPassword";
            Object[] valueArray = new Object[1];
            valueArray[0] = pst;
            passwordDelta.value = valueArray;

            MidpointModel3WebService.ItemDeltaType[] itemDeltaList = new MidpointModel3WebService.ItemDeltaType[1];
            itemDeltaList[0] = passwordDelta;
            objDeltaType.itemDelta = itemDeltaList;

            odt[0] = objDeltaType;

            string test =  odt.ToString();

            MidpointModel3WebService.executeChanges request = new executeChanges(odt, meot);
            executeChangesResponse response = modelPort.executeChanges(request);
            response.deltaOperationList[]

            System.Console.WriteLine("Result: '" + response.deltaOperationList.Length.ToString() + "' for user oid: '" + oid + "'");
        }

*/



/*
                /// <summary>
                /// Creates a new userDelta with the new password for the given user, then uses
                /// the given model port to transmit userDelta to Midpoint.
                /// </summary>
                /// <param name="modelPort">The model port to transmit new userDelta back to Midpoint.</param>
                /// <param name="oid">The user ID.</param>
                /// <param name="newPassword">The new password value.</param>


                public static void changeUserPassword(modelPortType modelPort, string oid, string newPassword)
                {
                    XmlDocument doc = new XmlDocument();

                    ObjectModificationType userDelta = new ObjectModificationType();
                    userDelta.oid = oid;

                    ItemDeltaType passwordDelta = new ItemDeltaType();
                    passwordDelta.modificationType = ModificationTypeType.replace;
                    // Set path value - webservices name is apparently 'Any'?
                    passwordDelta.Any = createPathElement("credentials/password", doc);
                    ItemDeltaTypeValue passwordValue = new ItemDeltaTypeValue();
                    // New passwordValue object so add at first index?
                    passwordValue.Any = new XmlElement[1];
                    passwordValue.Any.SetValue(toPasswordElement(NS_COMMON, createProtectedString(newPassword), doc), 0);
                    passwordDelta.value = passwordValue;
                    // New userDelta object so add at first index?
                    userDelta.modification = new ItemDeltaType[1];
                    userDelta.modification.SetValue(passwordDelta, 0);

                    modifyObject request = new modifyObject(getTypeUri(new UserType()), userDelta);
                    modifyObjectResponse response = modelPort.modifyObject(request);

                    System.Console.WriteLine("Result: '" + response.result.status.ToString() + "' for user oid: '" + oid + "'");
                }

                /// <summary>
                /// Searches for the given user using the given Midpoint model port.
                /// Returns the UserType object for the user if they exist.
                /// </summary>
                /// <param name="modelPort">The model port used to run search Midpoint.</param>
                /// <param name="username">The username to search for.</param>
                /// <returns>The UserType object for the requested user, or null if not found.</returns>
                public static UserType searchUserByName(modelPortType modelPort, string username)
                {
                    // WARNING: in a real case make sure that the username is properly escaped before putting it in XML
                    XmlElement filter = parseElement(
                                    "<equal xmlns='" + SEARCHUSER_NS + "' xmlns:c='" + NS_COMMON + "' >" +
                                        "<path>c:name</path>" +
                                        "<value>" + username + "</value>" +
                                    "</equal>"
                    );
                    QueryType query = new QueryType();
                    // Set filter value - webservices name is apparently 'Any'?
                    query.Any = filter;
                    // Create an empty array since it can't be uninitialised
                    ObjectOperationOptionsType[] options = new ObjectOperationOptionsType[0];

                    searchObjects request = new searchObjects(getTypeUri(new UserType()), query, options);
                    searchObjectsResponse response = modelPort.searchObjects(request);

                    ObjectListType objectList = response.objectList;
                    ObjectType[] objects = objectList.@object;

                    if (objects != null)
                    {
                        switch (objects.Length)
                        {
                            case 0:
                                return null;
                                break;
                            case 1:
                                return (UserType)objects[0];
                                break;
                            default:
                                throw new ArgumentException("Expected to find a single user with username '" + username + "' but found " + objects.Length + " users instead");
                        }
                    }
                    else
                    {
                        return null;
                    }
                }
        */

        /// <summary>
        /// Creates a new model port for with the administrator credentials.
        /// Has a default endpoint URL but this can be overridden by passing in a value for the first element in the args parameter. 
        /// </summary>
        /// <param name="args">If the first argument is defined it overrides the default endpoint URL. Any other args are ignored.</param>
        /// <returns>The new model port.</returns>
        public static MidpointModel3WebService.modelPortType createModelPort(String[] args)
        {
            string endpointUrl = DEFAULT_ENDPOINT_URL;

            if (args.Length > 0)
            {
                endpointUrl = args[0];
            }

            MidpointModel3WebService.modelPortTypeClient modelService = new MidpointModel3WebService.modelPortTypeClient();
            modelService.ClientCredentials.UserName.UserName = ADM_USERNAME;
            modelService.ClientCredentials.UserName.Password = ADM_PASSWORD;

            modelService.Endpoint.Behaviors.Add(new InspectorBehavior(new ClientInspector(new SecurityHeader(ADM_USERNAME, ADM_PASSWORD))));
            MidpointModel3WebService.modelPortType modelPort = modelService.ChannelFactory.CreateChannel(new EndpointAddress(endpointUrl));

            return modelPort;
        }

        #endregion

        #region Private Methods

        /// <summary>
        /// Defines the qualified name of XML element then calls createTextElement to create it.
        /// </summary>
        /// <param name="stringPath">Path ending for qualified name.</param>
        /// <param name="doc">The XML document object.</param>
        /// <returns>The new XML element.</returns>
        private static XmlElement createPathElement(string stringPath, XmlDocument doc)
        {
            string pathDeclaration = "declare default namespace '" + NS_COMMON + "'; " + stringPath;
            return createTextElement(SEARCHUSER_NS, pathDeclaration, doc);
        }

        /// <summary>
        /// Creates a new XML element with the given qualified name and value.
        /// </summary>
        /// <param name="qname">The qualified name for the XML element.</param>
        /// <param name="value">The value that the element should hold.</param>
        /// <param name="doc">The XML document object.</param>
        /// <returns>The new XML element.</returns>
        private static XmlElement createTextElement(string qname, string value, XmlDocument doc)
        {
            XmlElement element = doc.CreateElement(COMMON_PATH, qname);
            element.InnerText = value;
            return element;
        }

        
        /// <summary>
        /// Creates a new XML element with the given qualified name and sets the ProtectedStringType object as the value.
        /// </summary>
        /// <param name="name">The qualified name of element.</param>
        /// <param name="value">The ProtectedStringType object containing encrypted password and encryption method info.</param>
        /// <param name="doc">The XML document.</param>
        /// <returns>The XML element.</returns>
        private static XmlElement toPasswordElement(string name, MidpointModel3WebService.ProtectedStringType value, XmlDocument doc)
        {
            XmlElement element = doc.CreateElement(COMMON_VALUE, name);
            XmlNode innerElement = doc.CreateElement(CLEAR_VALUE, name);
            innerElement.InnerText = value.clearValue;
            element.AppendChild(innerElement);
            return element;
        }

        /// <summary>
        /// Initialise a ProtectedStringType object with the given clear value.
        /// </summary>
        /// <param name="clearValue">The clear value to use.</param>
        /// <returns>The new ProtectedStringType object.</returns>
        private static MidpointModel3WebService.ProtectedStringType createProtectedString(string clearValue)
        {
            MidpointModel3WebService.ProtectedStringType protectedString = new MidpointModel3WebService.ProtectedStringType();
            protectedString.clearValue = clearValue;
            return protectedString;
        }

        /// <summary>
        /// Creates an XML document with the given XML string and then parses it
        /// to find the first child element (internally calls getFirstChildElement
        /// to actually find the element).
        /// </summary>
        /// <param name="stringXml">The XML string used to create document.</param>
        /// <returns>The first child element.</returns>
        private static XmlElement parseElement(string stringXml)
        {
            XmlDocument document = new XmlDocument();
            document.LoadXml(stringXml);
            return getFirstChildElement(document);
        }

        /// <summary>
        /// Finds the first child element of the given XML node.
        /// </summary>
        /// <param name="parent">The node to parse.</param>
        /// <returns>First child element.</returns>
        public static XmlElement getFirstChildElement(XmlNode parent)
        {
            if (parent != null && parent.ChildNodes != null)
            {
                XmlNodeList nodes = parent.ChildNodes;
                for (int i = 0; i < nodes.Count; i++)
                {
                    XmlNode child = nodes.Item(i);
                    if (child.NodeType == XmlNodeType.Element)
                    {
                        return (XmlElement)child;
                    }
                }
            }

            return null;
        }

        /// <summary>
        /// Append the object type to the Midpoint namespace URL to get the typeURI.
        /// </summary>
        /// <param name="type">The object for which the type is required.</param>
        /// <returns>The type URI.</returns>
        private static string getTypeUri(object type)
        {
            return NS_COMMON + "#" + type.GetType().Name;
        }

        #endregion
    }
}
