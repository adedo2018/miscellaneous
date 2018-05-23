package com.powermock.employee;

import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.InOrder;
import org.mockito.Mockito;
import org.powermock.api.mockito.PowerMockito;
import org.powermock.core.classloader.annotations.PrepareForTest;
import org.powermock.modules.junit4.PowerMockRunner;

@RunWith(PowerMockRunner.class)
@PrepareForTest(Employee.class)
public class EmployeeServiceTest {

	@Test
	public void shouldReturnTheCountOfEmployeesUsingTheDomainClass() {
		PowerMockito.mockStatic(Employee.class);
		PowerMockito.when(Employee.count()).thenReturn(900);

		EmployeeService employeeService = new EmployeeService();
		Assert.assertEquals(900, employeeService.getEmployeeCount());
	}

	@Test
	public void shouldReturnTrueWhenIncrementOf10PercentageIsGivenSuccessfully() {
		PowerMockito.mockStatic(Employee.class);
		PowerMockito.doNothing().when(Employee.class);
		Employee.giveIncrementOf(10);

		EmployeeService employeeService = new EmployeeService();
		Assert.assertTrue(employeeService.giveIncrementToAllEmployeesOf(10));
	}

	@Test
	public void shouldReturnFalseWhenIncrementOf10PercentageIsNotGivenSuccessfully() {
		PowerMockito.mockStatic(Employee.class);
		PowerMockito.doThrow(new IllegalStateException()).when(Employee.class);
		Employee.giveIncrementOf(10);

		EmployeeService employeeService = new EmployeeService();
		Assert.assertFalse(employeeService.giveIncrementToAllEmployeesOf(10));
	}

	@Before
	public void initialize() {
		PowerMockito.mockStatic(Employee.class);
		PowerMockito.doNothing().when(Employee.class);
		Employee.giveIncrementOf(9);
	}

	@Test
	public void shouldInvoke_giveIncrementOfMethodOnEmployeeWhileGivingIncrement() {
		EmployeeService employeeService = new EmployeeService();
		employeeService.giveIncrementToAllEmployeesOf(9);

		PowerMockito.verifyStatic();
		Employee.giveIncrementOf(9);
	}

	@Test
	public void shouldCreateNewEmployeeIfEmployeeIsNew() {
		Employee mock = PowerMockito.mock(Employee.class);
		PowerMockito.when(mock.isNew()).thenReturn(true);

		EmployeeService employeeService = new EmployeeService();
		employeeService.saveEmployee(mock);

		Mockito.verify(mock).create();

		Mockito.verify(mock, Mockito.never()).update();
	}

	@Test
	public void shouldUpdateEmployeeIfEmployeeExists() {
		Employee mock = PowerMockito.mock(Employee.class);
		PowerMockito.when(mock.isNew()).thenReturn(false);

		EmployeeService employeeService = new EmployeeService();
		employeeService.saveEmployee(mock);

		Mockito.verify(mock).update();

		Mockito.verify(mock, Mockito.never()).create();
	}

	@Test
	public void shouldInvokeIsNewBeforeInvokingCreate() {
		Employee mock = PowerMockito.mock(Employee.class);

		EmployeeService employeeService = new EmployeeService();
		employeeService.saveEmployee(mock);

		InOrder inOrder = Mockito.inOrder(mock);

		inOrder.verify(mock).isNew();
		inOrder.verify(mock).update();
		inOrder.verify(mock, Mockito.never()).create();
	}
}
