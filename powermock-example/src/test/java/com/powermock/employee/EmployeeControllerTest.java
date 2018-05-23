package com.powermock.employee;

import org.junit.Assert;
import org.junit.Test;
import org.mockito.Mockito;
import org.mockito.invocation.InvocationOnMock;
import org.mockito.stubbing.Answer;
import org.powermock.api.mockito.PowerMockito;

public class EmployeeControllerTest {

	@Test
	public void shouldReturnCountOfEmployeesFromTheService() {
		EmployeeService mock = PowerMockito.mock(EmployeeService.class);

		PowerMockito.when(mock.getEmployeeCount()).thenReturn(10);

		EmployeeController employeeController = new EmployeeController(mock);
		Assert.assertEquals(10, employeeController.getEmployeeCount());
	}

	@Test
	public void shouldReturnCountOfEmployeesFromTheServiceWithDefaultAnswer() {
		EmployeeService mock = PowerMockito.mock(EmployeeService.class, new Answer<Integer>() {
			@Override
			public Integer answer(InvocationOnMock invocation) {
				return 10;
			}
		});

		EmployeeController employeeController = new EmployeeController(mock);
		Assert.assertEquals(10, employeeController.getEmployeeCount());
	}

	@Test
	public void shouldInvokeSaveEmployeeOnTheServiceWhileSavingTheEmployee() {
		EmployeeService mock = PowerMockito.mock(EmployeeService.class);

		EmployeeController employeeController = new EmployeeController(mock);

		Employee employee = new Employee();
		employeeController.saveEmployee(employee);

		Mockito.verify(mock).saveEmployee(employee);
	}

	@Test
	public void shouldInvokeSaveEmployeeOnTheServiceWhileSavingTheEmployeeWithMockSettings() {
		EmployeeService mock = PowerMockito.mock(EmployeeService.class, Mockito.withSettings().name("EmployeeServiceMock").verboseLogging());

		EmployeeController employeeController = new EmployeeController(mock);

		Employee employee = new Employee();
		employeeController.saveEmployee(employee);

		Mockito.verify(mock).saveEmployee(employee);
	}
}
