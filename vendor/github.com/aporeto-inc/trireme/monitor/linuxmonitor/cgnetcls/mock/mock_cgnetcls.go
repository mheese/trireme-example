// Automatically generated by MockGen. DO NOT EDIT!
// Source: interfaces.go

// nolint
package mock_cgnetcls

import (
	gomock "github.com/golang/mock/gomock"
)

// Mock of Cgroupnetcls interface
type MockCgroupnetcls struct {
	ctrl     *gomock.Controller
	recorder *_MockCgroupnetclsRecorder
}

// Recorder for MockCgroupnetcls (not exported)
type _MockCgroupnetclsRecorder struct {
	mock *MockCgroupnetcls
}

func NewMockCgroupnetcls(ctrl *gomock.Controller) *MockCgroupnetcls {
	mock := &MockCgroupnetcls{ctrl: ctrl}
	mock.recorder = &_MockCgroupnetclsRecorder{mock}
	return mock
}

func (_m *MockCgroupnetcls) EXPECT() *_MockCgroupnetclsRecorder {
	return _m.recorder
}

func (_m *MockCgroupnetcls) Creategroup(cgroupname string) error {
	ret := _m.ctrl.Call(_m, "Creategroup", cgroupname)
	ret0, _ := ret[0].(error)
	return ret0
}

func (_mr *_MockCgroupnetclsRecorder) Creategroup(arg0 interface{}) *gomock.Call {
	return _mr.mock.ctrl.RecordCall(_mr.mock, "Creategroup", arg0)
}

func (_m *MockCgroupnetcls) AssignMark(cgroupname string, mark uint64) error {
	ret := _m.ctrl.Call(_m, "AssignMark", cgroupname, mark)
	ret0, _ := ret[0].(error)
	return ret0
}

func (_mr *_MockCgroupnetclsRecorder) AssignMark(arg0, arg1 interface{}) *gomock.Call {
	return _mr.mock.ctrl.RecordCall(_mr.mock, "AssignMark", arg0, arg1)
}

func (_m *MockCgroupnetcls) AddProcess(cgroupname string, pid int) error {
	ret := _m.ctrl.Call(_m, "AddProcess", cgroupname, pid)
	ret0, _ := ret[0].(error)
	return ret0
}

func (_mr *_MockCgroupnetclsRecorder) AddProcess(arg0, arg1 interface{}) *gomock.Call {
	return _mr.mock.ctrl.RecordCall(_mr.mock, "AddProcess", arg0, arg1)
}

func (_m *MockCgroupnetcls) RemoveProcess(cgroupname string, pid int) error {
	ret := _m.ctrl.Call(_m, "RemoveProcess", cgroupname, pid)
	ret0, _ := ret[0].(error)
	return ret0
}

func (_mr *_MockCgroupnetclsRecorder) RemoveProcess(arg0, arg1 interface{}) *gomock.Call {
	return _mr.mock.ctrl.RecordCall(_mr.mock, "RemoveProcess", arg0, arg1)
}

func (_m *MockCgroupnetcls) DeleteCgroup(cgroupname string) error {
	ret := _m.ctrl.Call(_m, "DeleteCgroup", cgroupname)
	ret0, _ := ret[0].(error)
	return ret0
}

func (_mr *_MockCgroupnetclsRecorder) DeleteCgroup(arg0 interface{}) *gomock.Call {
	return _mr.mock.ctrl.RecordCall(_mr.mock, "DeleteCgroup", arg0)
}

func (_m *MockCgroupnetcls) Deletebasepath(contextID string) bool {
	ret := _m.ctrl.Call(_m, "Deletebasepath", contextID)
	ret0, _ := ret[0].(bool)
	return ret0
}

func (_mr *_MockCgroupnetclsRecorder) Deletebasepath(arg0 interface{}) *gomock.Call {
	return _mr.mock.ctrl.RecordCall(_mr.mock, "Deletebasepath", arg0)
}
