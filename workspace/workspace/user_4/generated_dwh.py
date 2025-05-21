from sqlalchemy import create_engine
import pandas as pd

# Load the CSV file
csv_file_path = '/workspace/workspace/user_4/raphy_20250517155642.csv'
data = pd.read_csv(csv_file_path)

# Transform the data for the fact table
fact_table = data[['EmployeeNumber', 'Attrition', 'MonthlyIncome', 
                   'YearsAtCompany', 'JobSatisfaction', 'PerformanceRating', 'OverTime']]

# Create employee dimension
dim_employee = data[['EmployeeNumber', 'Age', 'Gender', 'DistanceFromHome', 
                     'HourlyRate', 'JobInvolvement', 'StandardHours']].drop_duplicates()

# Create job dimension
dim_job = data[['JobRole', 'Department', 'JobLevel', 'Education', 'EducationField', 
                 'YearsInCurrentRole']].drop_duplicates()

# Create performance dimension
dim_performance = data[['PerformanceRating', 'JobSatisfaction',
                         'RelationshipSatisfaction', 'EnvironmentSatisfaction']].drop_duplicates()

# Create SQLite database
db_path = '/workspace/workspace/user_4/database.db'
engine = create_engine(f'sqlite:///{db_path}')

# Load the data into the SQLite database
fact_table.to_sql('Employee_Fact', engine, index=False, if_exists='replace')
dim_employee.to_sql('Dim_Employee', engine, index=False, if_exists='replace')
dim_job.to_sql('Dim_Job', engine, index=False, if_exists='replace')
dim_performance.to_sql('Dim_Performance', engine, index=False, if_exists='replace')

# Close the engine connection
engine.dispose()
