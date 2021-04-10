// Copyright 2017-2021 Google LLC.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//

package com.google.apigee.callouts.wssecdsig;

import java.util.HashMap;

public class TestCase implements Comparable {

    private String _testName;
    private String _description;
    private String _input; // filename
    private HashMap<String,String> _properties; // JSON hash
    private HashMap<String,String> _expected; // JSON hash
    private HashMap<String,String> _context; // JSON hash

    // getters
    public String getTestName() { return _testName; }
    public String getDescription() { return _description; }
    public String getInput() { return _input; }
    public HashMap<String,String> getProperties() { return _properties; }
    public HashMap<String,String> getContext() { return _context; }
    public HashMap<String,String> getExpected() { return _expected; }

    // setters
    public void setTestName(String n) { _testName = n; }
    public void setDescription(String d) { _description = d; }
    public void setInput(String f) { _input = f; }
    public void setExpected(HashMap<String,String> hash) { _expected = hash; }
    public void setContext(HashMap<String,String> hash) { _context = hash; }
    public void setProperties(HashMap<String,String> hash) { _properties = hash; }

    @Override
    public int compareTo(Object tc) {
        return getTestName().compareTo( ((TestCase)tc).getTestName() );
    }
}
